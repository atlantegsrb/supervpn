//go:build darwin

package tun

import (
	"testing"
	"time"
)

// newTestBPF builds a darwinBPF with no real file descriptor — only the
// loop-guard state is exercised.
func newTestBPF(localMAC [6]byte) *darwinBPF {
	b := &darwinBPF{
		fd:       -1,
		iface:    "test0",
		dedupMap: make(map[uint64]time.Time),
		hubMACs:  make(map[[6]byte]time.Time),
	}
	b.localMAC = localMAC
	return b
}

func ethFrame(dst, src [6]byte, payloadLen int) []byte {
	f := make([]byte, 14+payloadLen)
	copy(f[0:6], dst[:])
	copy(f[6:12], src[:])
	f[12], f[13] = 0x08, 0x00 // IPv4
	return f
}

var (
	macLocal  = [6]byte{0x02, 0, 0, 0, 0, 0x01} // the Mac's own en7
	macRemote = [6]byte{0x02, 0, 0, 0, 0, 0x02} // station behind the hub
	macLAN    = [6]byte{0x02, 0, 0, 0, 0, 0x03} // machine on the local segment
	macBcast  = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// The core regression: a frame injected from the hub that echoes back via
// SEESENT/TX-loopback must NOT be forwarded to the hub, even when its bytes no
// longer hash-match what was written (hardware padding, appended FCS, delay).
// Forwarding it makes the hub relearn the remote MAC behind this session and
// black-hole its traffic — the "appears for a second, then gone" failure.
func TestLoopGuard_SuppressesEchoWithAlteredBytes(t *testing.T) {
	b := newTestBPF(macLocal)

	injected := ethFrame(macLAN, macRemote, 40)
	b.hubMACRecord(injected)

	// Echo comes back padded/FCS-altered so the content hash cannot match.
	echo := append(append([]byte{}, injected...), 0xde, 0xad, 0xbe, 0xef, 0x00)
	if b.dedupSeen(echo) {
		t.Fatal("precondition: altered echo must defeat the byte-hash dedup")
	}
	if !b.loopSeen(echo) {
		t.Fatal("loop guard failed to suppress the echo of an injected frame")
	}
}

// Host-originated traffic is exactly why BIOCSSEESENT is enabled — it must
// always reach the hub, never be mistaken for an echo.
func TestLoopGuard_PassesHostOriginatedFrames(t *testing.T) {
	b := newTestBPF(macLocal)

	// Even if the hub somehow echoed a frame sourced from our own MAC, our MAC
	// must never be registered as a hub-side station.
	b.hubMACRecord(ethFrame(macRemote, macLocal, 40))

	hostFrame := ethFrame(macRemote, macLocal, 40)
	if b.loopSeen(hostFrame) {
		t.Fatal("host-originated frame was wrongly suppressed as a loop echo")
	}
}

// Traffic from a real machine on the local segment must pass through.
func TestLoopGuard_PassesLocalSegmentTraffic(t *testing.T) {
	b := newTestBPF(macLocal)
	b.hubMACRecord(ethFrame(macLAN, macRemote, 40)) // remote is hub-side

	local := ethFrame(macRemote, macLAN, 40) // LAN machine → remote
	if b.loopSeen(local) {
		t.Fatal("local segment traffic was wrongly suppressed")
	}
}

// Broadcast injected from the hub echoes back with the originator's source MAC,
// so it is caught by the same rule.
func TestLoopGuard_SuppressesBroadcastEcho(t *testing.T) {
	b := newTestBPF(macLocal)
	arp := ethFrame(macBcast, macRemote, 28)
	b.hubMACRecord(arp)
	if !b.loopSeen(arp) {
		t.Fatal("broadcast echo from a hub-side station was not suppressed")
	}
}

func TestLoopGuard_ExpiresAndIgnoresRunts(t *testing.T) {
	b := newTestBPF(macLocal)
	b.hubMACRecord(ethFrame(macLAN, macRemote, 40))

	// Back-date the entry past the TTL: the station is no longer known hub-side.
	b.hubMu.Lock()
	b.hubMACs[macRemote] = time.Now().Add(-(hubMACTTL + time.Second))
	b.hubMu.Unlock()
	if b.loopSeen(ethFrame(macLAN, macRemote, 40)) {
		t.Fatal("expired hub-side MAC must no longer suppress frames")
	}

	// Runts must not panic.
	b.hubMACRecord([]byte{1, 2, 3})
	if b.loopSeen([]byte{1, 2, 3}) {
		t.Fatal("runt frame must not be treated as a loop")
	}
}
