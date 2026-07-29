//go:build darwin

// BPF (Berkeley Packet Filter) L2 bridge for macOS.
//
// Unlike utun (which is L3), BPF binds directly to a physical NIC and captures
// full Ethernet frames — including source/destination MAC, EtherType, and payload.
// Writes to a BPF device inject frames back into the same NIC.
//
// No kernel extension or third-party driver is required.
// Access to /dev/bpf* requires root (or the 'com.apple.security.network.client'
// entitlement with a TCC/BPF exemption on newer macOS).
//
// Setup sequence:
//   open /dev/bpfN  → BIOCSETIF (bind NIC) → BIOCIMMEDIATE → BIOCPROMISC
//   → BIOCSRTIMEOUT (100 ms read timeout for ctx cancellation)
//   → BIOCSHDRCMPLT=1 (inject frames with the source MAC we supply — without
//     this the kernel rewrites it to the NIC's own MAC and bridging breaks)
//   → BIOCSSEESENT=1 (capture self-sent frames so Mac host traffic reaches hub)
//   → BIOCGBLEN (get read buffer size)
//
// Read returns one or more BPF-framed packets per call. Each is preceded by a
// bpf_hdr (Tstamp+Caplen+Datalen+Hdrlen); consecutive packets are aligned to
// BPF_WORDALIGN (4-byte) boundaries.  We return frames one at a time; any
// additional packets in the same read buffer are queued in darwinBPF.pending.
//
// Bridge loop prevention: with BIOCSSEESENT=1, frames we inject via WriteFrame
// reappear in BPF reads (via SEESENT and/or the driver's TX loopback on newer
// macOS/arm64).  WriteFrame records a hash of each injected frame; ReadFrame
// drops any frame whose hash matches a recently-injected one (300 ms TTL).
// Kernel-sent frames (Mac host pings, ARP, ZGW probes) are NOT in the dedup
// map and pass through to the hub — that is intentional.
package tun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/atlanteg/supervpn/internal/bridge"
)

const (
	bpfDedupTTL = 300 * time.Millisecond
	// hubMACTTL is how long a source MAC seen in an injected (hub→local) frame is
	// remembered as "this station lives behind the hub". Matches the server hub's
	// MAC table TTL so the two views expire together.
	hubMACTTL = 5 * time.Minute
	// hubSweepInterval bounds how often the hubMACs map is scanned for expiry;
	// WriteFrame is on the hot path, so the scan must not run per frame.
	hubSweepInterval = time.Second
)

type darwinBPF struct {
	fd      int
	iface   string
	bufSize int
	pending [][]byte // frames already read but not yet returned

	dedupMu   sync.Mutex
	dedupMap  map[uint64]time.Time // frame hash → time injected
	dedupDrops atomic.Uint64       // total frames dropped by dedup

	// localMAC is the bound NIC's own hardware address. Frames the Mac's kernel
	// sends carry it as source and MUST reach the hub (that is why SEESENT is on),
	// so it is never treated as a hub-side station.
	localMAC [6]byte
	hubMu    sync.Mutex
	// hubMACs holds source MACs observed in frames we injected from the hub.
	// Those stations are, by definition, NOT on the local segment — so a frame
	// read back with such a source MAC can only be our own injection echoing via
	// SEESENT/TX-loopback. See loopSeen.
	hubMACs      map[[6]byte]time.Time
	lastHubSweep time.Time
	loopDrops    atomic.Uint64
}

// openBPF opens a BPF device bound to ifaceName for L2 Ethernet capture/inject.
func openBPF(ifaceName string) (*darwinBPF, error) {
	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}

	// Bind to the interface (struct ifreq: 16-byte name + 16-byte union).
	var ifreq [32]byte
	copy(ifreq[:unix.IFNAMSIZ], ifaceName)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSETIF, uintptr(unsafe.Pointer(&ifreq[0]))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSETIF %s: %w", ifaceName, errno)
	}

	// Return packets immediately on arrival (don't wait for buffer to fill).
	one := uint32(1)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCIMMEDIATE, uintptr(unsafe.Pointer(&one))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCIMMEDIATE: %w", errno)
	}

	// Promiscuous: capture all frames, not just those addressed to our MAC.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCPROMISC, 0); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCPROMISC: %w", errno)
	}

	// Read timeout: 100 ms so ReadFrame can wake up to check ctx.Done().
	// Must use unix.Timeval (int64 Sec) — arm64 macOS rejects Timeval32.
	tv := unix.Timeval{Sec: 0, Usec: 100_000}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSRTIMEOUT, uintptr(unsafe.Pointer(&tv))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSRTIMEOUT: %w", errno)
	}

	// "Header complete": write the link-level header EXACTLY as we supply it.
	//
	// This flag is initialized to ZERO by default, and at zero the interface
	// output routine overwrites the source MAC of every injected frame with this
	// NIC's own address. For an L2 bridge that is fatal: a frame relayed from a
	// remote station reaches the local segment appearing to come from the Mac, so
	// the local machine addresses its replies to the Mac's MAC. Those replies then
	// arrive at the hub with the Mac's own MAC as destination, the hub resolves
	// that to this very session and drops it as a self-loop — the peer is briefly
	// visible (its broadcasts still carry a correct source) but no traffic ever
	// completes. Setting it to one preserves true L2 transparency; it is also what
	// libpcap does for packet injection.
	hdrComplete := uint32(1)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSHDRCMPLT, uintptr(unsafe.Pointer(&hdrComplete))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSHDRCMPLT: %w", errno)
	}

	// Capture self-sent frames so the Mac host's own traffic (pings, ARP,
	// ZGW probes) is forwarded to the hub in bridge mode.
	// Frames we inject via WriteFrame are excluded by the dedup + loop guard,
	// both of which depend on the source MAC surviving injection unmodified —
	// i.e. on BIOCSHDRCMPLT above.
	one2 := uint32(1)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSSEESENT, uintptr(unsafe.Pointer(&one2))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSSEESENT: %w", errno)
	}

	// Get kernel read buffer size.
	bufLen := uint32(0)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCGBLEN, uintptr(unsafe.Pointer(&bufLen))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCGBLEN: %w", errno)
	}

	b := &darwinBPF{
		fd:       fd,
		iface:    ifaceName,
		bufSize:  int(bufLen),
		dedupMap: make(map[uint64]time.Time),
		hubMACs:  make(map[[6]byte]time.Time),
	}
	// The NIC's own MAC identifies frames sent by this Mac's kernel, which must be
	// forwarded to the hub rather than treated as loop echoes.
	if ni, err := net.InterfaceByName(ifaceName); err == nil && len(ni.HardwareAddr) >= 6 {
		copy(b.localMAC[:], ni.HardwareAddr[:6])
		log.Printf("bpf/darwin: bound %s mac=%s (loop guard active)", ifaceName, ni.HardwareAddr)
	} else {
		log.Printf("bpf/darwin: WARNING: could not read %s hardware address (%v) — "+
			"loop guard cannot whitelist host-originated frames", ifaceName, err)
	}
	return b, nil
}

// openBPFDevice finds and opens the first available /dev/bpfN device.
func openBPFDevice() (int, error) {
	for i := 0; i < 256; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		if err == unix.EBUSY {
			continue // device in use, try next
		}
		return -1, fmt.Errorf("bpf/darwin: open %s: %w", path, err)
	}
	return -1, fmt.Errorf("bpf/darwin: no available /dev/bpf device (are you root?)")
}

// bpfWordAlign rounds up to BPF_WORDALIGN (4-byte alignment).
func bpfWordAlign(n int) int { return (n + 3) &^ 3 }

// frameHash returns a 64-bit hash of a frame for dedup purposes.
// Short frames are zero-padded to 60 bytes before hashing to match
// what the NIC delivers after hardware padding.
func frameHash(frame []byte) uint64 {
	const minEth = 60
	if len(frame) < minEth {
		var padded [minEth]byte
		copy(padded[:], frame)
		h := sha256.Sum256(padded[:])
		return binary.LittleEndian.Uint64(h[:8])
	}
	h := sha256.Sum256(frame)
	return binary.LittleEndian.Uint64(h[:8])
}

// dedupRecord records the frame hash as recently injected.
func (b *darwinBPF) dedupRecord(frame []byte) {
	now := time.Now()
	b.dedupMu.Lock()
	b.dedupMap[frameHash(frame)] = now
	for k, t := range b.dedupMap {
		if now.Sub(t) > bpfDedupTTL {
			delete(b.dedupMap, k)
		}
	}
	b.dedupMu.Unlock()
}

// dedupSeen returns true if the frame was recently injected (bridge loop).
// It checks the frame both as-is and with the last 4 bytes stripped,
// because some NICs append a 4-byte FCS/CRC to the captured copy, causing
// the BPF-read frame to be 4 bytes longer than what was written.
func (b *darwinBPF) dedupSeen(frame []byte) bool {
	b.dedupMu.Lock()
	t, ok := b.dedupMap[frameHash(frame)]
	if !ok && len(frame) > 4 {
		t, ok = b.dedupMap[frameHash(frame[:len(frame)-4])]
	}
	b.dedupMu.Unlock()
	return ok && time.Since(t) < bpfDedupTTL
}

// hubMACRecord notes the source MAC of a frame injected from the hub, marking
// that station as living behind the hub rather than on the local segment.
func (b *darwinBPF) hubMACRecord(frame []byte) {
	if len(frame) < 12 {
		return
	}
	var src [6]byte
	copy(src[:], frame[6:12])
	if src == b.localMAC {
		// The hub echoed a frame sourced from our own NIC — that is a loop on the
		// far side, not a hub-side station. Never block our own MAC.
		return
	}
	now := time.Now()
	b.hubMu.Lock()
	b.hubMACs[src] = now
	if now.Sub(b.lastHubSweep) > hubSweepInterval {
		for k, t := range b.hubMACs {
			if now.Sub(t) > hubMACTTL {
				delete(b.hubMACs, k)
			}
		}
		b.lastHubSweep = now
	}
	b.hubMu.Unlock()
}

// loopSeen reports whether a frame read from the NIC is our own injection
// echoing back. A frame whose SOURCE MAC belongs to a station we have been
// injecting from the hub cannot have originated on the local segment, so it must
// be an echo — regardless of whether its bytes still hash-match what we wrote
// (hardware padding, FCS, and delivery delay all break byte-exact matching).
//
// Forwarding such an echo to the hub is what makes the remote machine "appear
// for a moment and then vanish": the hub relearns that MAC behind THIS session,
// and unicast traffic for it is then black-holed into the local segment.
func (b *darwinBPF) loopSeen(frame []byte) bool {
	if len(frame) < 12 {
		return false
	}
	var src [6]byte
	copy(src[:], frame[6:12])
	if src == b.localMAC {
		return false // host-originated: must reach the hub
	}
	b.hubMu.Lock()
	t, ok := b.hubMACs[src]
	b.hubMu.Unlock()
	return ok && time.Since(t) < hubMACTTL
}

// ReadFrame returns one Ethernet frame. Blocks until a frame arrives or ctx
// is cancelled. Multiple frames from one BPF read are queued internally.
func (b *darwinBPF) ReadFrame(ctx context.Context) ([]byte, error) {
	for {
		// Return queued frames before doing another read.
		for len(b.pending) > 0 {
			f := b.pending[0]
			b.pending = b.pending[1:]
			if b.dedupSeen(f) {
				n := b.dedupDrops.Add(1)
				if n <= 10 || n%100 == 0 {
					log.Printf("bpf/darwin: dedup drop #%d src=%s dst=%s len=%d",
						n, fmtMACSlice(f[6:12]), fmtMACSlice(f[0:6]), len(f))
				}
				continue
			}
			// Byte-exact dedup missed it (padding/FCS/timing) — fall back to the
			// source-MAC loop guard, which does not depend on the bytes surviving
			// the round trip intact.
			if b.loopSeen(f) {
				n := b.loopDrops.Add(1)
				if n <= 10 || n%100 == 0 {
					log.Printf("bpf/darwin: loop drop #%d src=%s dst=%s len=%d "+
						"(hub-side MAC seen on local segment — echo suppressed)",
						n, fmtMACSlice(f[6:12]), fmtMACSlice(f[0:6]), len(f))
				}
				continue
			}
			return f, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		buf := make([]byte, b.bufSize)
		n, err := unix.Read(b.fd, buf)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue // read timeout — re-check ctx
		}
		if err != nil {
			return nil, fmt.Errorf("bpf/darwin: read: %w", err)
		}

		// Parse all BPF-framed packets from the buffer.
		off := 0
		for off+int(unix.SizeofBpfHdr) <= n {
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
			frameStart := off + int(hdr.Hdrlen)
			frameEnd := frameStart + int(hdr.Caplen)
			if frameEnd > n {
				break
			}
			frame := make([]byte, hdr.Caplen)
			copy(frame, buf[frameStart:frameEnd])
			b.pending = append(b.pending, frame)
			off += bpfWordAlign(int(hdr.Hdrlen) + int(hdr.Caplen))
		}
	}
}

// WriteFrame injects an Ethernet frame into the bound NIC.
func (b *darwinBPF) WriteFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	b.dedupRecord(frame)
	b.hubMACRecord(frame)
	_, err := unix.Write(b.fd, frame)
	return err
}

func (b *darwinBPF) Close() error   { return unix.Close(b.fd) }
func (b *darwinBPF) IfName() string { return b.iface }

func fmtMACSlice(b []byte) string {
	if len(b) < 6 {
		return "?"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

var _ bridge.Framer = (*darwinBPF)(nil)
