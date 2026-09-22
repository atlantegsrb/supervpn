// supervpn-server — L2 VPN server with multi-hub support.
// Listens on UDP (primary) and TCP+TLS (fallback) for client connections.
// Each Hub is an independent L2 broadcast domain (transparent Ethernet switch).
//
// Usage:
//
//	supervpn-server [-config /etc/supervpn/server.toml]
//	supervpn-server hashpw <password>
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atlanteg/supervpn/internal/auth"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/crypto"
	"github.com/atlanteg/supervpn/internal/fec"
	"github.com/atlanteg/supervpn/internal/fragment"
	"github.com/atlanteg/supervpn/internal/hub"
	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
	"github.com/atlanteg/supervpn/internal/update"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", config.DefaultServerConfigPath(), "config file")
	flag.Parse()

	if len(os.Args) >= 2 && os.Args[1] == "hashpw" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: supervpn-server hashpw <password>")
			os.Exit(1)
		}
		wireHex := auth.WireHash(os.Args[2])
		h, err := auth.HashPassword(wireHex)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(h)
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "reality-keygen" {
		priv, pub, err := transport.GenerateRealityKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("private_key = %q\n", transport.EncodeRealityKey(priv))
		fmt.Printf("public_key  = %q\n", transport.EncodeRealityKey(pub))
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "reality-genpool" {
		runRealityGenpool(os.Args[2:])
		return
	}

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Try peer servers as mirrors so servers update each other when GitHub is unreachable.
	update.CheckAndUpdate(version, update.AssetServer, update.DefaultMirrors())

	log.Printf("supervpn-server %s starting: UDP=%s hubs=%d", version, cfg.Listen, len(cfg.Hubs))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mgr := hub.NewManager()
	for _, hcfg := range cfg.Hubs {
		h := hub.New(hcfg.ID, hcfg.Name)
		mgr.Add(h)
		h.StartMACPurge(ctx)
		log.Printf("hub %d %q ready", hcfg.ID, hcfg.Name)
	}

	numWorkers := runtime.GOMAXPROCS(0)
	srv := &Server{
		cfg:          cfg,
		manager:      mgr,
		sessions:     make(map[uint32]*Session),
		kicked:       make(map[string]time.Time),
		bannedIPs:    make(map[string]struct{}),
		ipToLogins:   make(map[string]map[string]bool),
		bannedLogins: make(map[string]map[uint16]bool),
		startTime:    time.Now(),
		udpJobs:      make(chan udpJob, numWorkers*64),
	}
	srv.pktPool.New = func() interface{} {
		b := make([]byte, 2048)
		return &b
	}
	// proto.HeaderSize(15) + crypto overhead(24+16) + max Ethernet frame(1518) ≈ 1573; 2048 covers it.
	srv.sendPktPool.New = func() interface{} {
		b := make([]byte, 2048)
		return &b
	}
	for i := 0; i < numWorkers; i++ {
		go srv.udpWorker(ctx)
	}
	srv.loadBannedIPs()
	srv.loadBannedLogins()
	srv.checkUpdateAssets()
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
	log.Println("shutdown complete")
}

// Session holds the per-client state for an authenticated VPN session.
type Session struct {
	ID            uint32
	HubID         uint16
	Login         string
	RemoteAddr    string    // IP:port of the client
	Mode          string    // "udp" or "tls"
	ConnectedAt   time.Time // when auth completed
	sendRaw       func([]byte) error
	sendRaw2      func([]byte) error // secondary send path; nil = no secondary
	secondaryAddr string             // remote addr of secondary path (for logging)
	closeConn     func()             // closes the underlying transport (no-op for UDP)
	closeConn2    func()             // closes secondary TLS conn (nil = no secondary)
	cipher        *crypto.Cipher
	replay        crypto.ReplayWindow
	pipe          *fec.Pipe
	// fragEnabled is true for UDP sessions: oversized frames are split into
	// FrameDataFrag pieces (so they don't IP-fragment and get DPI-dropped) and
	// reassembled via reasm before forwarding to the hub. Off over TLS/Reality.
	fragEnabled   bool
	fragID        atomic.Uint32
	reasm         *fragment.Reassembler
	// orderMu makes "FEC decode → hub.Forward" atomic per session. The decoder
	// releases frames in strict (blockID, pktIdx) order, but its callers run
	// concurrently (UDP worker pool, secondary path, stale flush) and could
	// invert that order between RecvData returning and Forward being called —
	// injecting reordering the VPN itself created. Taken after cipher.Open so
	// AES-GCM decryption still runs in parallel across workers.
	orderMu       sync.Mutex
	cancel        context.CancelFunc // cancels per-session goroutines (e.g. FEC flush)
	lastSeenNano  atomic.Int64       // Unix nanoseconds; updated lock-free on every data/repair packet
	framesRx      atomic.Int64       // frames received from this client and forwarded to hub
	framesTx      atomic.Int64       // frames sent to this client from hub
	hubSendCalls  atomic.Int64       // times hub called client.Send (pre-FEC)
	mu            sync.Mutex
}

const kickBlockDuration = 5 * time.Minute

// udpJob carries one received UDP datagram to a worker goroutine.
type udpJob struct {
	pkt    []byte
	raddr  *net.UDPAddr
	sendFn func([]byte) error
	mode   string // "udp" or "udp2"
	sec    bool   // secondary path flag
}

// Server handles auth, data forwarding, and ping/pong over UDP and TLS/TCP.
type Server struct {
	cfg            *config.ServerConfig
	manager        *hub.Manager
	conn           *net.UDPConn
	conn2          *net.UDPConn // secondary UDP listener on port+1
	sessions       map[uint32]*Session
	kicked         map[string]time.Time       // login → blocked until; prevents immediate reconnect after kick
	bannedIPs      map[string]struct{}        // IP (no port) → permanently banned until explicit unban
	ipToLogins     map[string]map[string]bool // IP → logins that were kicked from it (for cleanup on unban)
	bannedLogins   map[string]map[uint16]bool // login → set of hub IDs where banned
	mu             sync.RWMutex
	pktPool        sync.Pool   // reusable packet buffers to reduce GC pressure
	sendPktPool    sync.Pool   // reusable output-packet buffers for sendFECData/sendFECRepair
	udpJobs        chan udpJob // worker-pool channel for incoming UDP packets
	startTime      time.Time
	tcpListenerUp  bool             // true once the primary TLS/TCP listener successfully binds
	tcp2ListenerUp bool             // true once the secondary TLS/TCP listener successfully binds
	updateAssets   map[string]int64 // asset name → size in bytes (0 = missing)
}

// Run starts the UDP listener (and TLS/TCP + status listeners if configured).
// udpWorker drains udpJobs and processes each packet without spawning
// a new goroutine per packet, eliminating per-packet GC pressure.
func (s *Server) udpWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-s.udpJobs:
			s.handlePacket(ctx, job.pkt, job.sendFn, job.raddr.String(), job.mode, func() {}, job.sec)
			// Return the buffer to the pool after handlePacket is done with pkt.
			buf := job.pkt[:cap(job.pkt)]
			s.pktPool.Put(&buf)
		}
	}
}

func (s *Server) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	log.Printf("listening UDP %s", s.cfg.Listen)

	if sec2Addr := deriveSecondaryAddr(s.cfg.Listen); sec2Addr != "" {
		if sec2UDPAddr, e := net.ResolveUDPAddr("udp", sec2Addr); e == nil {
			if conn2, e := net.ListenUDP("udp", sec2UDPAddr); e == nil {
				s.conn2 = conn2
				log.Printf("listening UDP secondary %s", sec2Addr)
				go s.runSecondaryUDP(ctx, conn2)
			} else {
				log.Printf("secondary UDP listen %s: %v", sec2Addr, e)
			}
		}
	}

	if s.cfg.ListenTCP != "" {
		go s.runTCPListener(ctx)
		go s.runTCPListener2(ctx)
	}
	if !s.cfg.Reality.Disable {
		go s.runRealityListener(ctx)
	}
	if s.cfg.StatusListen != "" {
		go s.runStatusServer(ctx)
	}
	// update_listen defaults to ":993" (IMAPS — privileged, near-universally
	// firewall-allowed, rarely DPI-filtered, and free of the nginx-on-:80
	// conflict). Clients/peers probe both :993 and :80 (see update.mirrorPorts),
	// so a server may still be put on :80 via config during migration.
	updateListen := s.cfg.UpdateListen
	if updateListen == "" {
		updateListen = ":993"
		s.cfg.UpdateListen = updateListen
	}
	go s.runUpdateServer(ctx)

	go s.cleanupLoop(ctx)

	// Single deadline covers the whole loop; context cancellation is checked
	// by the workers. The receive loop itself only needs to unblock on shutdown.
	conn.SetReadDeadline(time.Time{}) // blocking reads
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		bufPtr := s.pktPool.Get().(*[]byte)
		buf := *bufPtr
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			s.pktPool.Put(bufPtr)
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		pkt := buf[:n]
		ra := raddr
		// Fast-path: repair and ping packets are cheap (no hub forward in normal
		// operation). Process them inline to avoid channel overhead — with K=1/R=2
		// repairs account for ~2/3 of all incoming UDP packets.
		if hdr, ok := proto.ParseHeader(pkt); ok {
			if hdr.Type == proto.FrameRepair || hdr.Type == proto.FramePing {
				sendFn := func(p []byte) error { _, err := s.conn.WriteToUDP(p, ra); return err }
				s.handlePacket(ctx, pkt, sendFn, ra.String(), "udp", func() {}, false)
				s.pktPool.Put(bufPtr)
				continue
			}
		}
		select {
		case s.udpJobs <- udpJob{
			pkt:    pkt,
			raddr:  ra,
			sendFn: func(p []byte) error { _, err := s.conn.WriteToUDP(p, ra); return err },
			mode:   "udp",
			sec:    false,
		}:
		default:
			// Worker pool saturated — drop packet rather than blocking the read loop.
			s.pktPool.Put(bufPtr)
		}
	}
}

func (s *Server) runTCPListener(ctx context.Context) {
	tlsCfg, err := transport.NewServerTLSConfig(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		log.Printf("TLS config error, TCP listener disabled: %v", err)
		return
	}
	ln, err := transport.ListenTLS(s.cfg.ListenTCP, tlsCfg)
	if err != nil {
		log.Printf("TLS listen %s FAILED: %v", s.cfg.ListenTCP, err)
		return
	}
	s.mu.Lock()
	s.tcpListenerUp = true
	s.mu.Unlock()
	log.Printf("listening TLS/TCP %s", s.cfg.ListenTCP)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TLS accept error: %v", err)
				continue
			}
		}
		go s.handleTCPConn(ctx, conn)
	}
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("TCP accept from %s", remoteAddr)

	tr, err := transport.AcceptTLS(conn)
	if err != nil {
		log.Printf("TCP %s: TLS handshake failed: %v", remoteAddr, err)
		return
	}
	log.Printf("TCP %s: TLS handshake ok", remoteAddr)
	defer func() {
		tr.Close()
		log.Printf("TCP %s: connection closed", remoteAddr)
	}()
	s.serveStream(ctx, tr, remoteAddr, "tls")
}

// serveStream runs the per-connection auth+data loop for a stream transport
// (TLS or Reality). It returns when the connection errors or ctx is cancelled.
func (s *Server) serveStream(ctx context.Context, tr transport.Transport, remoteAddr, mode string) {
	sendReply := func(pkt []byte) error {
		return tr.Send(transport.Frame{Data: pkt})
	}
	closeConn := func() { tr.Close() }

	var sessionID uint32
	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			if sessionID != 0 {
				s.removeSession(sessionID)
				log.Printf("%s %s: session %d lost: %v", mode, remoteAddr, sessionID, err)
			} else {
				log.Printf("%s %s: pre-auth error: %v", mode, remoteAddr, err)
			}
			return
		}
		if sid := s.handlePacket(ctx, f.Data, sendReply, remoteAddr, mode, closeConn, false); sid != 0 {
			sessionID = sid
			log.Printf("%s %s: session %d established", mode, remoteAddr, sessionID)
		}
	}
}

// runRealityListener accepts Reality (VLESS+Reality-style) connections.
// Authorized clients are served like TLS clients; probers are transparently
// proxied to the configured dest site by AcceptReality.
func (s *Server) runRealityListener(ctx context.Context) {
	rc := s.cfg.Reality
	var privs []string
	if rc.PrivateKey != "" {
		privs = append(privs, rc.PrivateKey)
	}
	privs = append(privs, rc.PrivateKeys...)
	if len(privs) == 0 {
		// Zero-config: fall back to the built-in default pool that matches the
		// public pool embedded in stock clients.
		privs = defaultRealityPrivatePool
	}
	params, err := transport.BuildRealityServerParams(
		privs, rc.Dest, rc.ServerNames, rc.ShortIDs, rc.TimeWindow,
		s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		log.Printf("Reality listener disabled: %v", err)
		return
	}
	ln, err := net.Listen("tcp", rc.Listen)
	if err != nil {
		log.Printf("Reality listen %s FAILED: %v", rc.Listen, err)
		return
	}
	log.Printf("listening Reality %s (dest=%s keys=%d pub=%s)", rc.Listen, rc.Dest, params.PoolSize(), params.PublicKeyBase64())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("Reality accept error: %v", err)
				continue
			}
		}
		go s.handleRealityConn(ctx, conn, params)
	}
}

// runRealityGenpool generates a matched Reality key pool: the public keys are
// written as a Go source file for embedding in the client, the private keys as
// a TOML snippet to deploy to servers. Usage: reality-genpool [N] [goFile] [privFile]
func runRealityGenpool(args []string) {
	n := 64
	goFile := "internal/transport/reality_pool.go"
	srvFile := "cmd/supervpn-server/reality_default_pool.go"
	privFile := "reality-private-pool.toml"
	if len(args) >= 1 && args[0] != "" {
		v, err := strconv.Atoi(args[0])
		if err != nil || v <= 0 {
			log.Fatalf("reality-genpool: invalid N %q", args[0])
		}
		n = v
	}
	if len(args) >= 2 {
		goFile = args[1]
	}
	if len(args) >= 3 {
		privFile = args[2]
	}

	pubs, privs, err := transport.GenerateRealityPool(n)
	if err != nil {
		log.Fatal(err)
	}

	var b strings.Builder
	b.WriteString("package transport\n\n")
	b.WriteString("// realityPublicPool is the embedded set of server Reality public keys (base64\n")
	b.WriteString("// X25519). When a client has no explicit [reality].public_key, it picks one of\n")
	b.WriteString("// these at random per connection, so no key needs to be distributed to clients\n")
	b.WriteString("// manually. The matching PRIVATE keys are deployed to servers via\n")
	b.WriteString("// [reality].private_keys (see `supervpn-server reality-genpool`).\n")
	b.WriteString("//\n")
	b.WriteString("// SECURITY NOTE: these are PUBLIC keys, but in the Reality scheme the server's\n")
	b.WriteString("// public key is the client-side credential. Shipping it in the (public) client\n")
	b.WriteString("// binary protects against generic active probing, yet a targeted adversary who\n")
	b.WriteString("// extracts the pool can defeat the dest fallback. The inner supervpn password\n")
	b.WriteString("// auth still fully protects VPN access.\n")
	b.WriteString("//\n")
	b.WriteString("// This file is generated; edit via reality-genpool rather than by hand.\n")
	b.WriteString("var realityPublicPool = []string{\n")
	for _, p := range pubs {
		fmt.Fprintf(&b, "\t%q,\n", p)
	}
	b.WriteString("}\n")
	if err := os.WriteFile(goFile, []byte(b.String()), 0644); err != nil {
		log.Fatalf("reality-genpool: write %s: %v", goFile, err)
	}

	// Server-side default private pool (package main), matching the public pool.
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	sb.WriteString("// defaultRealityPrivatePool is the built-in Reality private-key pool used when\n")
	sb.WriteString("// the server config specifies no private_key / private_keys. It matches the\n")
	sb.WriteString("// PUBLIC pool embedded in clients (internal/transport/reality_pool.go), so a\n")
	sb.WriteString("// zero-config server and a stock client interoperate out of the box.\n")
	sb.WriteString("//\n")
	sb.WriteString("// SECURITY NOTE: this default pool is committed to the (public) repo and shipped\n")
	sb.WriteString("// in the server binary, so it is effectively public. It protects against generic\n")
	sb.WriteString("// active probing only. For a hardened deployment, regenerate a private pool with\n")
	sb.WriteString("// `supervpn-server reality-genpool N`, set it in [reality].private_keys, and ship\n")
	sb.WriteString("// the matching client build. Inner supervpn password auth always protects VPN\n")
	sb.WriteString("// access regardless.\n")
	sb.WriteString("//\n")
	sb.WriteString("// This file is generated; edit via reality-genpool rather than by hand.\n")
	sb.WriteString("var defaultRealityPrivatePool = []string{\n")
	for _, p := range privs {
		fmt.Fprintf(&sb, "\t%q,\n", p)
	}
	sb.WriteString("}\n")
	if err := os.WriteFile(srvFile, []byte(sb.String()), 0644); err != nil {
		log.Fatalf("reality-genpool: write %s: %v", srvFile, err)
	}

	var t strings.Builder
	t.WriteString("# Reality private-key pool — DEPLOY TO SERVERS ONLY.\n")
	t.WriteString("# Paste under [reality] in each server's config. NEVER commit this file or\n")
	t.WriteString("# ship it in any binary; the matching public keys are embedded in clients.\n")
	t.WriteString("private_keys = [\n")
	for _, p := range privs {
		fmt.Fprintf(&t, "  %q,\n", p)
	}
	t.WriteString("]\n")
	if err := os.WriteFile(privFile, []byte(t.String()), 0600); err != nil {
		log.Fatalf("reality-genpool: write %s: %v", privFile, err)
	}

	fmt.Printf("Generated %d Reality keypairs.\n", n)
	fmt.Printf("  public pool   → %s   (commit; embedded in clients)\n", goFile)
	fmt.Printf("  server default → %s   (commit; built-in server pool)\n", srvFile)
	fmt.Printf("  private pool  → %s   (optional; for [reality].private_keys — DO NOT commit)\n", privFile)
}

func (s *Server) handleRealityConn(ctx context.Context, conn net.Conn, params transport.RealityServerParams) {
	remoteAddr := conn.RemoteAddr().String()
	tr, authorized, err := transport.AcceptReality(ctx, conn, params)
	if err != nil {
		log.Printf("Reality %s: %v", remoteAddr, err)
		return
	}
	if !authorized {
		// Prober/invalid auth: AcceptReality already spliced to dest and closed.
		log.Printf("Reality %s: unauthenticated — proxied to dest", remoteAddr)
		return
	}
	log.Printf("Reality %s: authorized", remoteAddr)
	defer func() {
		tr.Close()
		log.Printf("Reality %s: connection closed", remoteAddr)
	}()
	s.serveStream(ctx, tr, remoteAddr, "reality")
}

// handlePacket dispatches one wire packet. secondary=true means the packet arrived
// on the secondary listener (port+1); auth is skipped and the path is auto-registered.
// Returns new session ID on auth, 0 otherwise.
func (s *Server) handlePacket(ctx context.Context, pkt []byte, sendReply func([]byte) error, remoteAddr, mode string, closeConn func(), secondary bool) uint32 {
	hdr, ok := proto.ParseHeader(pkt)
	if !ok {
		return 0
	}
	payload := pkt[proto.HeaderSize:]
	switch hdr.Type {
	case proto.FrameAuth:
		if !secondary {
			return s.handleAuth(ctx, payload, sendReply, remoteAddr, mode, closeConn)
		}
	case proto.FrameData:
		s.handleData(hdr, payload, sendReply, remoteAddr, secondary)
	case proto.FrameDataFrag:
		s.handleFrag(hdr, payload, sendReply, remoteAddr, secondary)
	case proto.FrameRepair:
		s.handleRepair(hdr, payload, sendReply, remoteAddr, secondary)
	case proto.FrameJoin:
		if secondary {
			s.handleJoin(hdr, sendReply, remoteAddr, closeConn)
		}
	case proto.FrameListHubs:
		s.handleListHubs(sendReply)
	case proto.FramePing:
		s.handlePing(hdr, sendReply)
	case proto.FrameUpdateGet:
		// Streaming the binary is only reliable over a stream transport
		// (Reality/TCP/TLS); never blast 16 KB chunks over UDP datagrams.
		if mode != "udp" && mode != "udp2" {
			s.handleUpdateGet(payload, sendReply)
		}
	}
	return 0
}

// handleUpdateGet streams a release asset to a peer over the (DPI-resistant)
// transport — the in-band update channel used when GitHub and the HTTP mirrors
// are blocked. Pre-auth: the assets are public release binaries. For the server
// binary it streams our own running executable (always matches /update/version,
// works even when this server could not fetch its own asset from GitHub).
func (s *Server) handleUpdateGet(payload []byte, sendReply func([]byte) error) {
	name := string(payload)
	sendData := func(status byte, data []byte) error {
		hdr := make([]byte, proto.HeaderSize)
		proto.Header{Type: proto.FrameUpdateData}.Marshal(hdr)
		frame := make([]byte, 0, proto.HeaderSize+1+len(data))
		frame = append(frame, hdr...)
		frame = append(frame, status)
		frame = append(frame, data...)
		return sendReply(frame)
	}

	// "version" is the in-band equivalent of GET /update/version — lets a peer
	// resolve the latest tag over Reality when all HTTP version checks are blocked.
	if name == "version" {
		_ = sendData(proto.UpdateChunk, []byte(version))
		_ = sendData(proto.UpdateEOF, nil)
		return
	}

	allowed := false
	for _, a := range clientAssets {
		if name == a {
			allowed = true
			break
		}
	}
	if !allowed {
		_ = sendData(proto.UpdateErr, []byte("unknown asset"))
		return
	}

	path := filepath.Join(s.updateDir(), name)
	if name == update.AssetServer {
		if exe, err := os.Executable(); err == nil {
			if resolved, e := filepath.EvalSymlinks(exe); e == nil {
				exe = resolved
			}
			if _, e := os.Stat(exe); e == nil {
				path = exe
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		_ = sendData(proto.UpdateErr, []byte("asset not available"))
		return
	}
	defer f.Close()

	buf := make([]byte, 16384)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := sendData(proto.UpdateChunk, buf[:n]); err != nil {
				return
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return
		}
	}
	_ = sendData(proto.UpdateEOF, nil)
}

// handleListHubs responds to a pre-auth hub discovery request with the list of
// configured hub IDs and names.  No credentials are required.
func (s *Server) handleListHubs(sendReply func([]byte) error) {
	var infos []proto.HubInfo
	for _, hcfg := range s.cfg.Hubs {
		infos = append(infos, proto.HubInfo{ID: hcfg.ID, Name: hcfg.Name})
	}
	payload := proto.MarshalHubList(infos)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameListHubs}.Marshal(hdr)
	_ = sendReply(append(hdr, payload...))
}

func (s *Server) handleAuth(ctx context.Context, payload []byte, sendReply func([]byte) error, remoteAddr, mode string, closeConn func()) uint32 {
	replyError := func(msg string) {
		ae := proto.AuthError{Message: msg}
		p := append([]byte{proto.AuthMsgError}, ae.Marshal()...)
		hdr := make([]byte, proto.HeaderSize)
		proto.Header{Type: proto.FrameAuth}.Marshal(hdr)
		_ = sendReply(append(hdr, p...))
	}

	if ip, _, err2 := net.SplitHostPort(remoteAddr); err2 == nil {
		s.mu.RLock()
		_, isBanned := s.bannedIPs[ip]
		s.mu.RUnlock()
		if isBanned {
			replyError("banned")
			return 0
		}
	}

	if len(payload) == 0 || payload[0] != proto.AuthMsgHello {
		return 0
	}
	hello, err := proto.ParseAuthHello(payload[1:])
	if err != nil {
		replyError("malformed auth request")
		return 0
	}
	h, ok := s.manager.Get(hello.HubID)
	if !ok {
		replyError("hub not found")
		return 0
	}

	var storedHash string
	hubUserCount := 0
	for _, hcfg := range s.cfg.Hubs {
		if hcfg.ID == hello.HubID {
			hubUserCount = len(hcfg.Users)
			for _, u := range hcfg.Users {
				if u.Login == hello.Login {
					storedHash = u.PasswordHash
				}
			}
		}
	}
	if storedHash == "" {
		// Diagnostic only — the wire reply stays generic so it does not reveal
		// which field was wrong. "hub has N user(s)" makes a stale/not-reloaded
		// config obvious (N=0 → the user block was never loaded).
		log.Printf("auth: login %q not found in hub %d config (hub has %d user(s)) — verify the user exists in THIS hub and that the server was restarted after editing the config",
			hello.Login, hello.HubID, hubUserCount)
		replyError("invalid credentials")
		return 0
	}

	wireHex := hex.EncodeToString(hello.PWHash[:])
	if err := auth.CheckPassword(wireHex, storedHash); err != nil {
		log.Printf("auth: bad password for login %q in hub %d — the value the client sent does not match the stored hash (check the password typed in the client)",
			hello.Login, hello.HubID)
		replyError("invalid credentials")
		return 0
	}
	log.Printf("auth: login %q authenticated in hub %d", hello.Login, hello.HubID)

	s.mu.RLock()
	blockedUntil, isBlocked := s.kicked[hello.Login]
	loginBanned := s.bannedLogins[hello.Login][hello.HubID]
	s.mu.RUnlock()
	if isBlocked && time.Now().Before(blockedUntil) {
		replyError(fmt.Sprintf("kicked: reconnect after %s", blockedUntil.UTC().Format(time.RFC3339)))
		return 0
	}
	if loginBanned {
		replyError("banned")
		return 0
	}

	sessionID := s.newSessionID()
	hubNetName := fmt.Sprintf("hub%d", hello.HubID)
	key, err := crypto.DeriveKey(wireHex, hubNetName, "server", hello.Login)
	if err != nil {
		replyError("internal error")
		return 0
	}
	cipher, err := crypto.NewCipher(key, sessionID)
	if err != nil {
		replyError("internal error")
		return 0
	}

	fecCfg := s.cfg.FEC.WithDefaults()
	now := time.Now()

	// Fragment oversized frames only on UDP (where they would IP-fragment and be
	// DPI-dropped) AND only toward clients that advertised FrameDataFrag support —
	// an old client would drop the unknown frame type and lose large frames.
	// Over TLS/Reality the stream transport handles segmentation.
	fragEnabled := mode == "udp" && hello.Flags&proto.FlagFragment != 0

	sess := &Session{
		ID:          sessionID,
		HubID:       hello.HubID,
		Login:       hello.Login,
		RemoteAddr:  remoteAddr,
		Mode:        mode,
		ConnectedAt: now,
		sendRaw:     sendReply,
		closeConn:   closeConn,
		cipher:      cipher,
		fragEnabled: fragEnabled,
		reasm:       fragment.NewReassembler(),
	}
	sess.lastSeenNano.Store(now.UnixNano())

	pipe, err := fec.NewPipe(
		fecCfg.K,
		fecCfg.R,
		fecCfg.RepairDelayDuration(),
		func(blockID uint32, pktIdx uint16, data []byte) error {
			return s.sendFECData(sess, blockID, pktIdx, data)
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			return s.sendFECRepair(sess, blockID, repairIdx, uint8(fecCfg.K), uint8(fecCfg.R), data)
		},
	)
	if err != nil {
		replyError("internal error")
		return 0
	}
	sess.pipe = pipe

	// Per-session context used to stop the FEC stale-block flush goroutine.
	// The server's root ctx is the parent so the goroutine also exits on shutdown.
	sCtx, sCancel := context.WithCancel(ctx)
	sess.cancel = sCancel

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	client := &hub.Client{
		SessionID: sessionID,
		Login:     hello.Login,
		Send: func(frame []byte) error {
			sess.hubSendCalls.Add(1)
			if sess.fragEnabled && fragment.NeedsSplit(frame, proto.MaxFramePlaintext) {
				return s.sendFrag(sess, frame)
			}
			return sess.pipe.Send(frame)
		},
	}
	h.Join(client)

	// Flush stale FEC blocks every 50ms; delivers buffered frames that are stuck
	// behind an unrecoverable gap (mid-block loss burst).
	pipe.StartFlush(sCtx, 200*time.Millisecond, &sess.orderMu, func(frame []byte) {
		if len(frame) < 14 {
			return
		}
		// orderMu is held by StartFlush across the whole batch — do not re-lock.
		sess.framesRx.Add(1)
		h.Forward(sessionID, frame)
	})
	pipe.StartRepairSender(sCtx)

	log.Printf("auth ok: %s@hub%d session=%d addr=%s mode=%s fec=K%d/R%d delay=%dms",
		hello.Login, hello.HubID, sessionID, remoteAddr, mode, fecCfg.K, fecCfg.R, fecCfg.RepairDelay)

	// Advertise the server's FEC params so the client can auto-adopt them, plus
	// the fragmentation capability so the client fragments its oversized frames too.
	var flags uint8
	if fragEnabled {
		flags |= proto.FlagFragment
	}
	okMsg := proto.AuthOK{
		SessionID:      sessionID,
		FecK:           uint8(fecCfg.K),
		FecR:           uint8(fecCfg.R),
		FecRepairDelay: uint16(fecCfg.RepairDelay),
		Flags:          flags,
	}
	p := append([]byte{proto.AuthMsgOK}, okMsg.Marshal()...)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameAuth}.Marshal(hdr)
	_ = sendReply(append(hdr, p...))
	return sessionID
}

func (s *Server) handleData(hdr proto.Header, payload []byte, sendReply func([]byte) error, remoteAddr string, secondary bool) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	sess.lastSeenNano.Store(time.Now().UnixNano())

	frame, err := sess.cipher.Open(payload, &sess.replay)
	if err != nil {
		return
	}

	if secondary {
		sess.mu.Lock()
		if sess.sendRaw2 == nil {
			sess.sendRaw2 = sendReply
			sess.secondaryAddr = remoteAddr
			log.Printf("session %d: secondary UDP path registered from %s", sess.ID, remoteAddr)
		}
		sess.mu.Unlock()
	}

	blockID, pktIdx := proto.UnpackDataSeq(hdr.Seq)
	sess.orderMu.Lock()
	defer sess.orderMu.Unlock()
	recovered, err := sess.pipe.RecvData(blockID, pktIdx, frame)
	if err != nil || recovered == nil {
		return
	}
	h, ok := s.manager.Get(sess.HubID)
	if !ok {
		return
	}
	for _, f := range recovered {
		if len(f) >= 14 {
			sess.framesRx.Add(1)
			h.Forward(hdr.SessionID, f)
		}
	}
}

// handleFrag decrypts one FrameDataFrag piece, reassembles the original frame,
// and forwards it to the hub once complete. Fragments bypass the FEC pipe; their
// redundancy comes from being sent on both UDP paths (the replay window and the
// reassembler both drop the duplicate copy).
func (s *Server) handleFrag(hdr proto.Header, payload []byte, sendReply func([]byte) error, remoteAddr string, secondary bool) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	sess.lastSeenNano.Store(time.Now().UnixNano())

	frame, err := sess.cipher.Open(payload, &sess.replay)
	if err != nil {
		return
	}

	if secondary {
		sess.mu.Lock()
		if sess.sendRaw2 == nil {
			sess.sendRaw2 = sendReply
			sess.secondaryAddr = remoteAddr
			log.Printf("session %d: secondary UDP path registered from %s", sess.ID, remoteAddr)
		}
		sess.mu.Unlock()
	}

	fragID, idx, count := proto.UnpackFragSeq(hdr.Seq)
	whole := sess.reasm.Add(fragID, idx, count, frame)
	if whole == nil || len(whole) < 14 {
		return
	}
	h, ok := s.manager.Get(sess.HubID)
	if !ok {
		return
	}
	sess.orderMu.Lock()
	sess.framesRx.Add(1)
	h.Forward(hdr.SessionID, whole)
	sess.orderMu.Unlock()
}

func (s *Server) handleRepair(hdr proto.Header, payload []byte, sendReply func([]byte) error, remoteAddr string, secondary bool) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	// Extract blockID before decrypting: skip the expensive cipher.Open for
	// repair packets whose block is already fully delivered (common at K=1/R=2).
	blockID, repairIdx, blockK, blockR := proto.UnpackRepairSeq(hdr.Seq)
	if sess.pipe.RepairBlockDone(blockID) {
		return
	}

	frame, err := sess.cipher.Open(payload, &sess.replay)
	if err != nil {
		return
	}

	if secondary {
		sess.mu.Lock()
		if sess.sendRaw2 == nil {
			sess.sendRaw2 = sendReply
			sess.secondaryAddr = remoteAddr
			log.Printf("session %d: secondary UDP path registered from %s", sess.ID, remoteAddr)
		}
		sess.mu.Unlock()
	}

	sess.orderMu.Lock()
	defer sess.orderMu.Unlock()
	recovered, err := sess.pipe.RecvRepair(blockID, repairIdx, blockK, blockR, frame)
	if err != nil || recovered == nil {
		return
	}
	h, ok := s.manager.Get(sess.HubID)
	if !ok {
		return
	}
	for _, f := range recovered {
		if len(f) >= 14 {
			sess.framesRx.Add(1)
			h.Forward(hdr.SessionID, f)
		}
	}
}

func (s *Server) handlePing(hdr proto.Header, sendReply func([]byte) error) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()

	if !ok {
		// Session not found — server likely restarted and lost in-memory state.
		// Send an auth error so the client detects the stale session immediately
		// and reconnects, instead of hanging "Connected" until keepalive timeout.
		errHdr := make([]byte, proto.HeaderSize)
		proto.Header{Type: proto.FrameAuth, SessionID: hdr.SessionID}.Marshal(errHdr)
		ae := proto.AuthError{Message: "session expired"}
		body := append([]byte{proto.AuthMsgError}, ae.Marshal()...)
		_ = sendReply(append(errHdr, body...))
		return
	}

	sess.lastSeenNano.Store(time.Now().UnixNano())

	pong := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FramePong, SessionID: hdr.SessionID}.Marshal(pong)
	_ = sendReply(pong)
}

func (s *Server) sendFECData(sess *Session, blockID uint32, pktIdx uint16, frame []byte) error {
	encrypted, err := sess.cipher.Seal(frame)
	if err != nil {
		return err
	}
	total := proto.HeaderSize + len(encrypted)
	bufPtr := s.sendPktPool.Get().(*[]byte)
	if cap(*bufPtr) < total {
		*bufPtr = make([]byte, total)
	}
	pkt := (*bufPtr)[:total]
	proto.Header{
		Type:      proto.FrameData,
		HubID:     sess.HubID,
		SessionID: sess.ID,
		Seq:       proto.PackDataSeq(blockID, pktIdx),
	}.Marshal(pkt[:proto.HeaderSize])
	copy(pkt[proto.HeaderSize:], encrypted)
	sess.framesTx.Add(1)
	sess.mu.Lock()
	send2 := sess.sendRaw2
	sess.mu.Unlock()
	err = sess.sendRaw(pkt)
	if send2 != nil {
		_ = send2(pkt)
	}
	s.sendPktPool.Put(bufPtr)
	return err
}

// sendFrag splits an oversized frame into FrameDataFrag pieces and sends each on
// both paths. Used instead of the FEC pipe for frames larger than one datagram's
// plaintext budget, so they survive DPI instead of IP-fragmenting.
func (s *Server) sendFrag(sess *Session, frame []byte) error {
	id := sess.fragID.Add(1)
	pieces := fragment.Split(frame, proto.MaxFramePlaintext)
	sess.mu.Lock()
	send2 := sess.sendRaw2
	sess.mu.Unlock()
	for i, pc := range pieces {
		encrypted, err := sess.cipher.Seal(pc)
		if err != nil {
			return err
		}
		total := proto.HeaderSize + len(encrypted)
		bufPtr := s.sendPktPool.Get().(*[]byte)
		if cap(*bufPtr) < total {
			*bufPtr = make([]byte, total)
		}
		pkt := (*bufPtr)[:total]
		proto.Header{
			Type:      proto.FrameDataFrag,
			HubID:     sess.HubID,
			SessionID: sess.ID,
			Seq:       proto.PackFragSeq(id, uint8(i), uint8(len(pieces))),
		}.Marshal(pkt[:proto.HeaderSize])
		copy(pkt[proto.HeaderSize:], encrypted)
		sess.framesTx.Add(1)
		_ = sess.sendRaw(pkt)
		if send2 != nil {
			_ = send2(pkt)
		}
		s.sendPktPool.Put(bufPtr)
	}
	return nil
}

func (s *Server) sendFECRepair(sess *Session, blockID uint32, repairIdx, blockK, blockR uint8, data []byte) error {
	encrypted, err := sess.cipher.Seal(data)
	if err != nil {
		return err
	}
	total := proto.HeaderSize + len(encrypted)
	bufPtr := s.sendPktPool.Get().(*[]byte)
	if cap(*bufPtr) < total {
		*bufPtr = make([]byte, total)
	}
	pkt := (*bufPtr)[:total]
	proto.Header{
		Type:      proto.FrameRepair,
		HubID:     sess.HubID,
		SessionID: sess.ID,
		Seq:       proto.PackRepairSeq(blockID, repairIdx, blockK, blockR),
	}.Marshal(pkt[:proto.HeaderSize])
	copy(pkt[proto.HeaderSize:], encrypted)
	sess.mu.Lock()
	send2 := sess.sendRaw2
	sess.mu.Unlock()
	err = sess.sendRaw(pkt)
	if send2 != nil {
		_ = send2(pkt)
	}
	s.sendPktPool.Put(bufPtr)
	return err
}

func (s *Server) newSessionID() uint32 {
	var b [4]byte
	rand.Read(b[:])
	id := binary.BigEndian.Uint32(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

func (s *Server) removeSession(id uint32) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if ok {
		if sess.cancel != nil {
			sess.cancel()
		}
		sess.mu.Lock()
		cc2 := sess.closeConn2
		sess.mu.Unlock()
		if cc2 != nil {
			cc2()
		}
		if h, ok2 := s.manager.Get(sess.HubID); ok2 {
			h.Leave(id)
		}
		log.Printf("session %d closed (%s)", id, sess.Login)
	}
}

func (s *Server) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.cleanupSessions()
		}
	}
}

func (s *Server) cleanupSessions() {
	deadline := time.Now().Add(-15 * time.Second)
	now := time.Now()
	s.mu.Lock()
	for id, sess := range s.sessions {
		stale := time.Unix(0, sess.lastSeenNano.Load()).Before(deadline)
		if stale {
			delete(s.sessions, id)
			if sess.cancel != nil {
				sess.cancel()
			}
			sess.mu.Lock()
			cc2 := sess.closeConn2
			sess.mu.Unlock()
			if cc2 != nil {
				cc2()
			}
			if h, ok := s.manager.Get(sess.HubID); ok {
				h.Leave(id)
			}
			log.Printf("session %d timed out (%s)", id, sess.Login)
		}
	}
	for login, until := range s.kicked {
		if now.After(until) {
			delete(s.kicked, login)
		}
	}
	s.mu.Unlock()
}

// ── Dual-path (secondary listener) ───────────────────────────────────────────

// deriveSecondaryAddr returns host:port+1 for the given host:port address.
func deriveSecondaryAddr(addr string) string {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port+1))
}

// runSecondaryUDP reads from the secondary UDP socket (port+1) and routes packets
// through handlePacket with secondary=true, enabling auto-registration of the
// client's secondary source address as sess.sendRaw2.
func (s *Server) runSecondaryUDP(ctx context.Context, conn *net.UDPConn) {
	conn.SetReadDeadline(time.Time{})
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		bufPtr := s.pktPool.Get().(*[]byte)
		buf := *bufPtr
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			s.pktPool.Put(bufPtr)
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("secondary UDP: read error: %v", err)
				return
			}
		}
		pkt := buf[:n]
		ra := raddr
		if hdr, ok := proto.ParseHeader(pkt); ok {
			if hdr.Type == proto.FrameRepair || hdr.Type == proto.FramePing {
				sendFn := func(p []byte) error { _, err := conn.WriteToUDP(p, ra); return err }
				s.handlePacket(ctx, pkt, sendFn, ra.String(), "udp2", func() {}, true)
				s.pktPool.Put(bufPtr)
				continue
			}
		}
		select {
		case s.udpJobs <- udpJob{
			pkt:    pkt,
			raddr:  ra,
			sendFn: func(p []byte) error { _, err := conn.WriteToUDP(p, ra); return err },
			mode:   "udp2",
			sec:    true,
		}:
		default:
			s.pktPool.Put(bufPtr)
		}
	}
}

// runTCPListener2 starts a secondary TLS/TCP listener on ListenTCP+1.
// Clients connect here as a second path; the first packet must be FrameJoin
// carrying the session ID obtained from the primary auth.
func (s *Server) runTCPListener2(ctx context.Context) {
	sec2Addr := deriveSecondaryAddr(s.cfg.ListenTCP)
	if sec2Addr == "" {
		return
	}
	tlsCfg, err := transport.NewServerTLSConfig(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		log.Printf("TLS secondary: config error: %v", err)
		return
	}
	ln, err := transport.ListenTLS(sec2Addr, tlsCfg)
	if err != nil {
		log.Printf("TLS secondary listen %s FAILED: %v", sec2Addr, err)
		return
	}
	s.mu.Lock()
	s.tcp2ListenerUp = true
	s.mu.Unlock()
	log.Printf("listening TLS/TCP secondary %s", sec2Addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TLS secondary accept error: %v", err)
				continue
			}
		}
		go s.handleTCPConn2(ctx, conn)
	}
}

// handleTCPConn2 manages one secondary TLS connection.
// It expects FrameJoin as the first packet to identify the session, then
// forwards FrameData/FrameRepair through the normal handlers.
func (s *Server) handleTCPConn2(ctx context.Context, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	tr, err := transport.AcceptTLS(conn)
	if err != nil {
		log.Printf("TCP secondary %s: TLS handshake failed: %v", remoteAddr, err)
		return
	}
	defer tr.Close()

	sendReply := func(pkt []byte) error {
		return tr.Send(transport.Frame{Data: pkt})
	}
	closeConn := func() { tr.Close() }

	var sessionID uint32
	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			if sessionID != 0 {
				s.mu.RLock()
				sess, ok := s.sessions[sessionID]
				s.mu.RUnlock()
				if ok {
					sess.mu.Lock()
					sess.sendRaw2 = nil
					sess.secondaryAddr = ""
					sess.closeConn2 = nil
					sess.mu.Unlock()
					log.Printf("TCP secondary %s: session %d secondary path lost", remoteAddr, sessionID)
				}
			}
			return
		}
		hdr, ok := proto.ParseHeader(f.Data)
		if !ok {
			continue
		}

		if sessionID == 0 {
			if hdr.Type == proto.FrameJoin && hdr.SessionID != 0 {
				s.handleJoin(hdr, sendReply, remoteAddr, closeConn)
				sessionID = hdr.SessionID
				log.Printf("TCP secondary %s: session %d registered", remoteAddr, sessionID)
			}
			continue
		}

		payload := f.Data[proto.HeaderSize:]
		switch hdr.Type {
		case proto.FrameData:
			s.handleData(hdr, payload, sendReply, remoteAddr, false)
		case proto.FrameRepair:
			s.handleRepair(hdr, payload, sendReply, remoteAddr, false)
		case proto.FramePing:
			s.handlePing(hdr, sendReply)
		}
	}
}

// handleJoin registers a TLS secondary connection as sess.sendRaw2.
func (s *Server) handleJoin(hdr proto.Header, sendReply func([]byte) error, remoteAddr string, closeConn func()) {
	if hdr.SessionID == 0 {
		return
	}
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	if sess.sendRaw2 == nil {
		sess.sendRaw2 = sendReply
		sess.secondaryAddr = remoteAddr
		sess.closeConn2 = closeConn
		log.Printf("session %d: secondary TLS path registered from %s", sess.ID, remoteAddr)
	}
	sess.mu.Unlock()
}

// ── Update mirror ────────────────────────────────────────────────────────────

// clientAssets lists every binary the server may serve as a mirror.
// Must stay in sync with the release artifacts published by CI.
var clientAssets = []string{
	// Server binary — served so peer servers can update each other.
	update.AssetServer,
	// CLI clients
	"supervpn-client-windows-amd64.exe",
	"supervpn-client-darwin-arm64",
	"supervpn-client-darwin-amd64",
	"supervpn-client-linux-amd64",
	"supervpn-client-linux-arm64",
	// GUI — macOS (universal app bundle zip + per-arch binaries)
	"supervpn-client-gui-darwin-arm64",
	"supervpn-client-gui-darwin-amd64",
	// GUI — Windows: Win32/Walk main client (amd64 + 32-bit Win7)
	"supervpn-client-gui-windows-amd64.exe",
	"supervpn-client-gui-windows-386.exe",
	// GUI — Windows: seema pre-configured minimal client
	"supervpn-seema-windows-amd64.exe",
	// GUI — Windows: bmgarage pre-configured minimal client
	"supervpn-bmgarage-windows-amd64.exe",
}

// updateDir returns the resolved directory for client assets.
func (s *Server) updateDir() string {
	if s.cfg.UpdateDir != "" {
		return s.cfg.UpdateDir
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "dist")
	}
	return "dist"
}

// checkUpdateAssets verifies that client binaries in updateDir match the server
// version. If a .mirror-version file records a different version (or is absent),
// all assets are re-downloaded so stale binaries from a previous deployment are
// replaced. Dev builds skip auto-download. Populates s.updateAssets.
func (s *Server) checkUpdateAssets() {
	dir := s.updateDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("update mirror: cannot create dir %s: %v", dir, err)
	}

	canFetch := version != "dev"
	if !canFetch {
		log.Printf("update mirror: dev build — skipping auto-download of client binaries")
	}

	// Check whether the cached binaries match the current server version.
	versionFile := filepath.Join(dir, ".mirror-version")
	cachedVer, _ := os.ReadFile(versionFile)
	stale := strings.TrimSpace(string(cachedVer)) != version

	if stale && canFetch {
		log.Printf("update mirror: refreshing client assets for %s", version)
	}

	assets := make(map[string]int64, len(clientAssets))
	for _, name := range clientAssets {
		path := filepath.Join(dir, name)
		if !stale {
			if fi, err := os.Stat(path); err == nil {
				log.Printf("update mirror: ok  %s  (%d bytes)", name, fi.Size())
				assets[name] = fi.Size()
				continue
			}
		}
		if !canFetch {
			log.Printf("update mirror: missing  %s", name)
			continue
		}
		log.Printf("update mirror: downloading  %s  (release %s) ...", name, version)
		if err := update.FetchAsset(version, name, path); err != nil {
			log.Printf("update mirror: download %s failed: %v", name, err)
			continue
		}
		fi, _ := os.Stat(path)
		log.Printf("update mirror: ready  %s  (%d bytes)", name, fi.Size())
		assets[name] = fi.Size()
	}

	// Write version stamp so next restart skips re-download when version matches.
	if canFetch {
		_ = os.WriteFile(versionFile, []byte(version), 0644)
	}

	s.mu.Lock()
	s.updateAssets = assets
	s.mu.Unlock()

	if s.cfg.StatusListen != "" {
		available := 0
		for _, sz := range assets {
			if sz > 0 {
				available++
			}
		}
		mirrorURL := s.mirrorURL()
		if available == len(clientAssets) {
			log.Printf("update mirror ready — clients: update_mirrors = [\"%s\"]", mirrorURL)
		} else {
			log.Printf("update mirror: %d/%d assets available at %s", available, len(clientAssets), mirrorURL)
		}
	}
}

// mirrorURL returns the client-facing base URL for the update mirror.
// Prefers update_listen when set; falls back to status_listen.
// Wildcards (0.0.0.0 / ::) are replaced with the UDP host; loopback triggers a warning.
func (s *Server) mirrorURL() string {
	listen := s.cfg.UpdateListen
	if listen == "" {
		listen = s.cfg.StatusListen
	}
	if listen == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen + "/update"
	}
	switch host {
	case "", "0.0.0.0", "::":
		if udpHost, _, e := net.SplitHostPort(s.cfg.Listen); e == nil &&
			udpHost != "" && udpHost != "0.0.0.0" && udpHost != "::" {
			host = udpHost
		} else {
			host = "<your_server_ip>"
		}
	case "127.0.0.1", "::1":
		src := "update_listen"
		if s.cfg.UpdateListen == "" {
			src = "status_listen"
		}
		log.Printf("update mirror: WARNING: %s is bound to loopback (%s) — "+
			"clients on other machines cannot reach the mirror", src, listen)
		host = "<your_server_ip>"
	}
	if port == "80" {
		return fmt.Sprintf("http://%s/update", host)
	}
	return fmt.Sprintf("http://%s:%s/update", host, port)
}

// handleUpdateAsset serves a client binary from updateDir, or a directory
// listing when the path is exactly /update/.
// Only names in clientAssets are allowed — path traversal is impossible.
func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/update/")
	if name == "" {
		s.handleUpdateListing(w, r)
		return
	}
	allowed := false
	for _, a := range clientAssets {
		if name == a {
			allowed = true
			break
		}
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}
	// For the server binary, prefer our OWN running executable: it always
	// matches /update/version and is available even when this server could not
	// download its own asset from GitHub into updateDir (GitHub CDN blocked).
	// This keeps the peer-mirror chain working server-to-server with no GitHub.
	if name == update.AssetServer {
		if exe, err := os.Executable(); err == nil {
			if resolved, err2 := filepath.EvalSymlinks(exe); err2 == nil {
				exe = resolved
			}
			if _, err3 := os.Stat(exe); err3 == nil {
				http.ServeFile(w, r, exe)
				return
			}
		}
	}
	http.ServeFile(w, r, filepath.Join(s.updateDir(), name))
}

func (s *Server) handleUpdateListing(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ver := version
	assets := make(map[string]int64, len(s.updateAssets))
	for k, v := range s.updateAssets {
		assets[k] = v
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>supervpn update mirror</title>"+
		"<style>body{font-family:monospace;padding:2em}table{border-collapse:collapse}"+
		"td,th{padding:4px 16px 4px 0;text-align:left}a{color:#0066cc}</style></head>"+
		"<body><h2>supervpn update mirror — %s</h2><table>"+
		"<tr><th>file</th><th>size</th></tr>\n", ver)
	for _, name := range clientAssets {
		size := assets[name]
		if size > 0 {
			fmt.Fprintf(w, "<tr><td><a href=\"/update/%s\">%s</a></td><td>%d bytes</td></tr>\n",
				name, name, size)
		} else {
			fmt.Fprintf(w, "<tr><td>%s</td><td><em>not available</em></td></tr>\n", name)
		}
	}
	fmt.Fprintf(w, "</table><p><a href=\"/update/version\">/update/version</a></p></body></html>")
}

// ── Status HTTP API ──────────────────────────────────────────────────────────

type statusResponse struct {
	Version        string              `json:"version"`
	Uptime         string              `json:"uptime"`
	UDPListen      string              `json:"udp_listen"`
	UDPListen2     string              `json:"udp_listen_2,omitempty"`
	TCPListen      string              `json:"tcp_listen,omitempty"`
	TCPListen2     string              `json:"tcp_listen_2,omitempty"`
	TCPListenerUp  bool                `json:"tcp_listener_up"`
	TCP2ListenerUp bool                `json:"tcp2_listener_up,omitempty"`
	Hubs           []hubStatus         `json:"hubs"`
	Blocked        map[string]string   `json:"blocked,omitempty"`       // login → blocked_until (RFC3339)
	BannedIPs      []string            `json:"banned_ips,omitempty"`    // permanently banned IPs
	BannedLogins   map[string][]uint16 `json:"banned_logins,omitempty"` // login → hub IDs where banned
	UpdateMirror   *mirrorStatus       `json:"update_mirror,omitempty"`
}

type mirrorStatus struct {
	URL    string            `json:"url"`
	Assets map[string]string `json:"assets"` // asset name → "ok (N bytes)" | "missing"
}

type hubStatus struct {
	ID       uint16          `json:"id"`
	Name     string          `json:"name"`
	Clients  []clientStatus  `json:"clients"`
	MACTable []macTableEntry `json:"mac_table"`
}

type macTableEntry struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip,omitempty"`
	Login     string `json:"login,omitempty"`
	SessionID uint32 `json:"session_id"`
	ExpiresIn string `json:"expires_in"`
}

type clientStatus struct {
	SessionID     uint32 `json:"session_id"`
	Login         string `json:"login"`
	RemoteAddr    string `json:"remote_addr"`
	SecondaryAddr string `json:"secondary_addr,omitempty"` // set when dual-path is active
	Mode          string `json:"mode"`
	ConnectedAt   string `json:"connected_at"`
	LastSeen      string `json:"last_seen"`
	Duration      string `json:"duration"`
	FramesRx      int64  `json:"frames_rx"`
	FramesTx      int64  `json:"frames_tx"`
	HubSendCalls  int64  `json:"hub_send_calls"`
}

func (s *Server) runStatusServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/api/hubs/", s.handleAPI)  // POST /api/hubs/{id}/kick/{session}; GET|POST /api/hubs/{id}/loginbans[/{login}]; POST /api/hubs/{id}/loginunbans/{login}
	mux.HandleFunc("/api/bans", s.handleBans)  // GET /api/bans
	mux.HandleFunc("/api/ips/", s.handleIPBan) // POST /api/ips/{ip}/ban|unban
	// Serve /update/* on status_listen only when update_listen is not configured.
	if s.cfg.UpdateListen == "" {
		mux.HandleFunc("/update/version", s.handleUpdateVersion)
		mux.HandleFunc("/update/", s.handleUpdateAsset)
	}

	srv := &http.Server{Addr: s.cfg.StatusListen, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("status API on http://%s/status", s.cfg.StatusListen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("status server error: %v", err)
	}
}

// runUpdateServer runs a dedicated HTTP listener for the client update mirror.
// Serves GET /update/version and GET /update/{asset} on cfg.UpdateListen.
func (s *Server) runUpdateServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/update/version", s.handleUpdateVersion)
	mux.HandleFunc("/update/", s.handleUpdateAsset)

	srv := &http.Server{Addr: s.cfg.UpdateListen, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("update mirror on http://%s/update", s.cfg.UpdateListen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("update server error: %v", err)
	}
}

// handleAPI dispatches management actions.
// Currently supports: POST /api/hubs/{hub_id}/kick/{session_id}
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Route loginbans/loginunbans to the dedicated handler.
	if len(parts) >= 4 && parts[0] == "api" && parts[1] == "hubs" &&
		(parts[3] == "loginbans" || parts[3] == "loginunbans") {
		s.handleLoginBan(w, r)
		return
	}

	// Path: /api/hubs/{hub_id}/kick/{session_id}
	if len(parts) == 4 && parts[0] == "api" && parts[1] == "hubs" && parts[3] == "kick" {
		http.Error(w, "use POST /api/hubs/{id}/kick/{session_id}", http.StatusBadRequest)
		return
	}
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "hubs" || parts[3] != "kick" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	sid64, err := strconv.ParseUint(parts[4], 10, 32)
	if err != nil {
		http.Error(w, "invalid session_id", http.StatusBadRequest)
		return
	}
	sessionID := uint32(sid64)

	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	if ok {
		delete(s.sessions, sessionID)
		s.kicked[sess.Login] = time.Now().Add(kickBlockDuration)
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	// Ban the IP so the client cannot reconnect from the same address.
	kickedIP, _, _ := net.SplitHostPort(sess.RemoteAddr)
	if kickedIP != "" {
		s.mu.Lock()
		s.bannedIPs[kickedIP] = struct{}{}
		if s.ipToLogins[kickedIP] == nil {
			s.ipToLogins[kickedIP] = make(map[string]bool)
		}
		s.ipToLogins[kickedIP][sess.Login] = true
		s.mu.Unlock()
		s.saveBannedIPs()
	}

	// Close transport (no-op for UDP; closes TCP connection immediately).
	sess.closeConn()
	sess.mu.Lock()
	cc2 := sess.closeConn2
	sess.mu.Unlock()
	if cc2 != nil {
		cc2()
	}

	if h, ok2 := s.manager.Get(sess.HubID); ok2 {
		h.Leave(sessionID)
	}
	log.Printf("kick: session %d (%s@hub%d, ip=%s) blocked login for %s and IP permanently",
		sessionID, sess.Login, sess.HubID, kickedIP, kickBlockDuration)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","session_id":%d,"login":%q,"banned_ip":%q}`, sessionID, sess.Login, kickedIP)
}

// ── IP ban helpers ────────────────────────────────────────────────────────────

func (s *Server) banFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "banned_ips.json"
	}
	return filepath.Join(filepath.Dir(exe), "banned_ips.json")
}

func (s *Server) loadBannedIPs() {
	data, err := os.ReadFile(s.banFilePath())
	if err != nil {
		return // first run or no file yet
	}
	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		log.Printf("ban: failed to parse %s: %v", s.banFilePath(), err)
		return
	}
	s.mu.Lock()
	for _, ip := range ips {
		s.bannedIPs[ip] = struct{}{}
	}
	s.mu.Unlock()
	log.Printf("ban: loaded %d banned IPs from %s", len(ips), s.banFilePath())
}

func (s *Server) saveBannedIPs() {
	s.mu.RLock()
	ips := make([]string, 0, len(s.bannedIPs))
	for ip := range s.bannedIPs {
		ips = append(ips, ip)
	}
	s.mu.RUnlock()
	sort.Strings(ips)
	data, _ := json.MarshalIndent(ips, "", "  ")
	if err := os.WriteFile(s.banFilePath(), data, 0644); err != nil {
		log.Printf("ban: failed to save %s: %v", s.banFilePath(), err)
	}
}

// kickSessionsByIP closes all active sessions whose remote IP matches ip
// and removes them from s.sessions. Must be called without s.mu held.
func (s *Server) kickSessionsByIP(ip string) {
	s.mu.Lock()
	var toKick []*Session
	for id, sess := range s.sessions {
		if sessIP, _, err := net.SplitHostPort(sess.RemoteAddr); err == nil && sessIP == ip {
			toKick = append(toKick, sess)
			delete(s.sessions, id)
			s.kicked[sess.Login] = time.Now().Add(kickBlockDuration)
			if s.ipToLogins[ip] == nil {
				s.ipToLogins[ip] = make(map[string]bool)
			}
			s.ipToLogins[ip][sess.Login] = true
		}
	}
	s.mu.Unlock()

	for _, sess := range toKick {
		sess.closeConn()
		sess.mu.Lock()
		cc2 := sess.closeConn2
		sess.mu.Unlock()
		if cc2 != nil {
			cc2()
		}
		if h, ok := s.manager.Get(sess.HubID); ok {
			h.Leave(sess.ID)
		}
		log.Printf("ban: kicked session %d (%s@hub%d) due to IP ban on %s", sess.ID, sess.Login, sess.HubID, ip)
	}
}

// GET /api/bans — list all permanently banned IPs.
func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	ips := make([]string, 0, len(s.bannedIPs))
	for ip := range s.bannedIPs {
		ips = append(ips, ip)
	}
	s.mu.RUnlock()
	sort.Strings(ips)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"banned_ips": ips})
}

// POST /api/ips/{ip}/ban  — permanently ban an IP and kick its sessions.
// POST /api/ips/{ip}/unban — remove a ban.
func (s *Server) handleIPBan(w http.ResponseWriter, r *http.Request) {
	// Path: /api/ips/{ip}/ban  or  /api/ips/{ip}/unban
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "ips" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	ip := parts[2]
	action := parts[3]
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid IP address", http.StatusBadRequest)
		return
	}

	switch action {
	case "ban":
		s.mu.Lock()
		s.bannedIPs[ip] = struct{}{}
		s.mu.Unlock()
		s.saveBannedIPs()
		s.kickSessionsByIP(ip)
		log.Printf("ban: IP %s banned via API", ip)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","action":"ban","ip":%q}`, ip)

	case "unban":
		s.mu.Lock()
		_, wasBanned := s.bannedIPs[ip]
		delete(s.bannedIPs, ip)
		// Also clear the temporary login block for all logins that were kicked from this IP.
		for login := range s.ipToLogins[ip] {
			delete(s.kicked, login)
		}
		delete(s.ipToLogins, ip)
		s.mu.Unlock()
		if wasBanned {
			s.saveBannedIPs()
		}
		log.Printf("ban: IP %s unbanned via API", ip)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","action":"unban","ip":%q,"was_banned":%v}`, ip, wasBanned)

	default:
		http.NotFound(w, r)
	}
}

// ── Login ban helpers ─────────────────────────────────────────────────────────

func (s *Server) loginBanFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "banned_logins.json"
	}
	return filepath.Join(filepath.Dir(exe), "banned_logins.json")
}

// bannedLoginsFile is the on-disk format: map[login][]hubID.
type bannedLoginsFile map[string][]uint16

func (s *Server) loadBannedLogins() {
	data, err := os.ReadFile(s.loginBanFilePath())
	if err != nil {
		return
	}
	var f bannedLoginsFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("loginban: failed to parse %s: %v", s.loginBanFilePath(), err)
		return
	}
	s.mu.Lock()
	for login, hubs := range f {
		s.bannedLogins[login] = make(map[uint16]bool, len(hubs))
		for _, h := range hubs {
			s.bannedLogins[login][h] = true
		}
	}
	s.mu.Unlock()
	log.Printf("loginban: loaded bans for %d logins from %s", len(f), s.loginBanFilePath())
}

func (s *Server) saveBannedLogins() {
	s.mu.RLock()
	f := make(bannedLoginsFile, len(s.bannedLogins))
	for login, hubs := range s.bannedLogins {
		ids := make([]uint16, 0, len(hubs))
		for h := range hubs {
			ids = append(ids, h)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		f[login] = ids
	}
	s.mu.RUnlock()
	data, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(s.loginBanFilePath(), data, 0644); err != nil {
		log.Printf("loginban: failed to save %s: %v", s.loginBanFilePath(), err)
	}
}

// kickSessionsByLogin closes all active sessions for login on hubID.
func (s *Server) kickSessionsByLogin(login string, hubID uint16) {
	s.mu.Lock()
	var toKick []*Session
	for id, sess := range s.sessions {
		if sess.Login == login && sess.HubID == hubID {
			toKick = append(toKick, sess)
			delete(s.sessions, id)
			s.kicked[login] = time.Now().Add(kickBlockDuration)
		}
	}
	s.mu.Unlock()

	for _, sess := range toKick {
		sess.closeConn()
		sess.mu.Lock()
		cc2 := sess.closeConn2
		sess.mu.Unlock()
		if cc2 != nil {
			cc2()
		}
		if h, ok := s.manager.Get(sess.HubID); ok {
			h.Leave(sess.ID)
		}
		log.Printf("loginban: kicked session %d (%s@hub%d) due to login ban", sess.ID, sess.Login, sess.HubID)
	}
}

// POST /api/hubs/{hub_id}/loginbans/{login}   — ban login on hub + kick sessions.
// POST /api/hubs/{hub_id}/loginunbans/{login}  — remove ban.
// GET  /api/hubs/{hub_id}/loginbans            — list banned logins on hub.
func (s *Server) handleLoginBan(w http.ResponseWriter, r *http.Request) {
	// Paths:
	//   /api/hubs/{hub_id}/loginbans
	//   /api/hubs/{hub_id}/loginbans/{login}
	//   /api/hubs/{hub_id}/loginunbans/{login}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "hubs" {
		http.NotFound(w, r)
		return
	}
	hubID64, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		http.Error(w, "invalid hub_id", http.StatusBadRequest)
		return
	}
	hubID := uint16(hubID64)
	action := parts[3] // "loginbans" or "loginunbans"

	// GET /api/hubs/{hub_id}/loginbans — list
	if r.Method == http.MethodGet && action == "loginbans" && len(parts) == 4 {
		s.mu.RLock()
		var logins []string
		for login, hubs := range s.bannedLogins {
			if hubs[hubID] {
				logins = append(logins, login)
			}
		}
		s.mu.RUnlock()
		sort.Strings(logins)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"hub_id": hubID, "banned_logins": logins})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if len(parts) != 5 {
		http.Error(w, "login required in path", http.StatusBadRequest)
		return
	}
	login := parts[4]

	switch action {
	case "loginbans":
		s.mu.Lock()
		if s.bannedLogins[login] == nil {
			s.bannedLogins[login] = make(map[uint16]bool)
		}
		s.bannedLogins[login][hubID] = true
		s.mu.Unlock()
		s.saveBannedLogins()
		s.kickSessionsByLogin(login, hubID)
		log.Printf("loginban: %s banned on hub%d via API", login, hubID)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","action":"ban","login":%q,"hub_id":%d}`, login, hubID)

	case "loginunbans":
		s.mu.Lock()
		wasBanned := s.bannedLogins[login][hubID]
		delete(s.bannedLogins[login], hubID)
		if len(s.bannedLogins[login]) == 0 {
			delete(s.bannedLogins, login)
		}
		s.mu.Unlock()
		if wasBanned {
			s.saveBannedLogins()
		}
		log.Printf("loginban: %s unbanned on hub%d via API", login, hubID)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","action":"unban","login":%q,"hub_id":%d,"was_banned":%v}`, login, hubID, wasBanned)

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleUpdateVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, version)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now()

	// Build session index by hub.
	type sessSnapshot struct {
		SessionID     uint32
		Login         string
		RemoteAddr    string
		SecondaryAddr string
		Mode          string
		ConnectedAt   time.Time
		LastSeen      time.Time
		FramesRx      int64
		FramesTx      int64
		HubSendCalls  int64
	}
	byHub := make(map[uint16][]sessSnapshot)

	s.mu.RLock()
	for _, sess := range s.sessions {
		sess.mu.Lock()
		snap := sessSnapshot{
			SessionID:     sess.ID,
			Login:         sess.Login,
			RemoteAddr:    sess.RemoteAddr,
			SecondaryAddr: sess.secondaryAddr,
			Mode:          sess.Mode,
			ConnectedAt:   sess.ConnectedAt,
			LastSeen:      time.Unix(0, sess.lastSeenNano.Load()),
			FramesRx:      sess.framesRx.Load(),
			FramesTx:      sess.framesTx.Load(),
			HubSendCalls:  sess.hubSendCalls.Load(),
		}
		sess.mu.Unlock()
		byHub[sess.HubID] = append(byHub[sess.HubID], snap)
	}
	s.mu.RUnlock()

	// Build hub list from config (preserves order, shows empty hubs too).
	hubs := make([]hubStatus, 0, len(s.cfg.Hubs))
	for _, hcfg := range s.cfg.Hubs {
		hs := hubStatus{ID: hcfg.ID, Name: hcfg.Name, Clients: []clientStatus{}, MACTable: []macTableEntry{}}
		for _, snap := range byHub[hcfg.ID] {
			hs.Clients = append(hs.Clients, clientStatus{
				SessionID:     snap.SessionID,
				Login:         snap.Login,
				RemoteAddr:    snap.RemoteAddr,
				SecondaryAddr: snap.SecondaryAddr,
				Mode:          snap.Mode,
				ConnectedAt:   snap.ConnectedAt.UTC().Format(time.RFC3339),
				LastSeen:      snap.LastSeen.UTC().Format(time.RFC3339),
				Duration:      now.Sub(snap.ConnectedAt).Truncate(time.Second).String(),
				FramesRx:      snap.FramesRx,
				FramesTx:      snap.FramesTx,
				HubSendCalls:  snap.HubSendCalls,
			})
		}
		if h, ok := s.manager.Get(hcfg.ID); ok {
			for _, rec := range h.MACTableSnapshot() {
				e := macTableEntry{
					MAC:       rec.MAC.String(),
					Login:     rec.Login,
					SessionID: rec.SessionID,
					ExpiresIn: rec.ExpiresIn.String(),
				}
				if rec.IP != nil {
					e.IP = rec.IP.String()
				}
				hs.MACTable = append(hs.MACTable, e)
			}
		}
		hubs = append(hubs, hs)
	}

	s.mu.RLock()
	blocked := make(map[string]string, len(s.kicked))
	for login, until := range s.kicked {
		if now.Before(until) {
			blocked[login] = until.UTC().Format(time.RFC3339)
		}
	}
	s.mu.RUnlock()

	s.mu.RLock()
	tcpUp := s.tcpListenerUp
	tcp2Up := s.tcp2ListenerUp
	s.mu.RUnlock()

	var mirror *mirrorStatus
	if s.cfg.StatusListen != "" {
		s.mu.RLock()
		assets := s.updateAssets
		s.mu.RUnlock()
		if assets != nil {
			assetInfo := make(map[string]string, len(assets))
			for _, name := range clientAssets {
				if sz := assets[name]; sz > 0 {
					assetInfo[name] = fmt.Sprintf("ok (%d bytes)", sz)
				} else {
					assetInfo[name] = "missing"
				}
			}
			mirror = &mirrorStatus{
				URL:    s.mirrorURL(),
				Assets: assetInfo,
			}
		}
	}

	s.mu.RLock()
	var bannedList []string
	for ip := range s.bannedIPs {
		bannedList = append(bannedList, ip)
	}
	var bannedLoginMap map[string][]uint16
	if len(s.bannedLogins) > 0 {
		bannedLoginMap = make(map[string][]uint16, len(s.bannedLogins))
		for login, hubs := range s.bannedLogins {
			ids := make([]uint16, 0, len(hubs))
			for h := range hubs {
				ids = append(ids, h)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			bannedLoginMap[login] = ids
		}
	}
	s.mu.RUnlock()
	sort.Strings(bannedList)

	resp := statusResponse{
		Version:        version,
		Uptime:         now.Sub(s.startTime).Truncate(time.Second).String(),
		UDPListen:      s.cfg.Listen,
		UDPListen2:     deriveSecondaryAddr(s.cfg.Listen),
		TCPListen:      s.cfg.ListenTCP,
		TCPListen2:     deriveSecondaryAddr(s.cfg.ListenTCP),
		TCPListenerUp:  tcpUp,
		TCP2ListenerUp: tcp2Up,
		Hubs:           hubs,
		UpdateMirror:   mirror,
	}
	if len(blocked) > 0 {
		resp.Blocked = blocked
	}
	if len(bannedList) > 0 {
		resp.BannedIPs = bannedList
	}
	if len(bannedLoginMap) > 0 {
		resp.BannedLogins = bannedLoginMap
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)
}
