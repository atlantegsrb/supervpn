// Package hub implements the server-side L2 Hub.
//
// A Hub is an isolated L2 broadcast domain. The server runs N independent hubs.
// Each hub maintains a MAC address table and forwards Ethernet frames between
// connected clients — transparent L2 bridging, exactly like a network switch.
//
// Topology:
//
//	Client A ──┐
//	Client B ──┤── Hub (L2 switch) ── (isolated per hub)
//	Client C ──┘
package hub

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const macTableTTL = 5 * time.Minute

// Client represents a connected VPN client session.
type Client struct {
	SessionID uint32
	Send      func(frame []byte) error
	Login     string
}

// Hub is a single L2 broadcast domain.
type Hub struct {
	mu       sync.RWMutex
	id       uint16
	name     string
	clients  map[uint32]*Client // sessionID → client
	macTable map[[6]byte]macEntry
	// MAC-flap diagnostics: a MAC repeatedly changing session indicates a client
	// looping frames back into the hub. Guarded by mu.
	lastFlapLog time.Time
	flapCount   uint64
}

type macEntry struct {
	sessionID uint32
	expires   time.Time
	ip        net.IP // last seen IPv4 for this MAC; nil if not yet observed
}

// MACRecord is one entry in the MAC address table, enriched with session login.
type MACRecord struct {
	MAC       net.HardwareAddr
	SessionID uint32
	Login     string  // empty if session no longer connected
	IP        net.IP  // nil if no IPv4 seen yet
	ExpiresIn time.Duration
}

func New(id uint16, name string) *Hub {
	return &Hub{
		id:       id,
		name:     name,
		clients:  make(map[uint32]*Client),
		macTable: make(map[[6]byte]macEntry),
	}
}

func (h *Hub) ID() uint16   { return h.id }
func (h *Hub) Name() string { return h.name }

// Join adds a client to the hub.
func (h *Hub) Join(c *Client) {
	h.mu.Lock()
	h.clients[c.SessionID] = c
	h.mu.Unlock()
}

// Leave removes a client from the hub.
func (h *Hub) Leave(sessionID uint32) {
	h.mu.Lock()
	delete(h.clients, sessionID)
	h.mu.Unlock()
}

// Forward delivers an Ethernet frame received from srcSession to the correct destination(s).
// It learns the source MAC address and does unicast/broadcast forwarding.
func (h *Hub) Forward(srcSession uint32, frame []byte) {
	if len(frame) < 12 {
		return
	}
	var dst, src [6]byte
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])

	// Fast path: if we already know this src MAC for this session with a fresh
	// TTL, skip the write lock and just do a read-lock dst lookup.
	h.mu.RLock()
	srcEntry, srcKnown := h.macTable[src]
	dstEntry, known := h.macTable[dst]
	h.mu.RUnlock()

	// A MAC that keeps moving between sessions means some client is echoing frames
	// back into the hub (an L2 loop). The symptom is a station that appears for an
	// instant and then goes unreachable, because unicast for it follows the wrong
	// session. Log it — rate-limited — so the culprit session is identifiable.
	moved := srcKnown && srcEntry.sessionID != srcSession

	needUpdate := !srcKnown ||
		srcEntry.sessionID != srcSession ||
		time.Until(srcEntry.expires) < time.Minute

	if moved {
		h.mu.Lock()
		shouldLog := time.Since(h.lastFlapLog) > 5*time.Second
		if shouldLog {
			h.lastFlapLog = time.Now()
		}
		h.flapCount++
		n := h.flapCount
		h.mu.Unlock()
		if shouldLog {
			log.Printf("hub%d: MAC %s moved session %d → %d (flap #%d) — "+
				"a client is likely looping frames back into the hub",
				h.id, fmtMAC(src), srcEntry.sessionID, srcSession, n)
		}
	}

	if needUpdate {
		// Slow path: write lock to update src MAC entry.
		var newIP net.IP
		if srcKnown {
			newIP = srcEntry.ip
		}
		if len(frame) >= 14 {
			etype := uint16(frame[12])<<8 | uint16(frame[13])
			switch etype {
			case 0x0806:
				if len(frame) >= 32 {
					newIP = cloneIP(frame[28:32])
				}
			case 0x0800:
				if len(frame) >= 30 {
					newIP = cloneIP(frame[26:30])
				}
			}
		}
		h.mu.Lock()
		h.macTable[src] = macEntry{sessionID: srcSession, expires: time.Now().Add(macTableTTL), ip: newIP}
		dstEntry, known = h.macTable[dst] // re-read under write lock
		h.mu.Unlock()
	}

	isBroadcast := dst == ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	isMulticast := dst[0]&0x01 != 0

	if known && !isBroadcast && !isMulticast {
		// Unicast to known destination.
		h.mu.RLock()
		c, ok := h.clients[dstEntry.sessionID]
		h.mu.RUnlock()
		if ok && c.SessionID == srcSession {
			// Self-loop: dst MAC is our own entry. Drop silently.
			return
		}
		if ok {
			_ = c.Send(frame)
			return
		}
		// Stale MAC entry: fall through to flood so the frame is not silently dropped.
	}

	// Broadcast / multicast / unknown unicast / stale unicast → flood to all except source.
	h.mu.RLock()
	targets := make([]*Client, 0, len(h.clients))
	for _, c := range h.clients {
		if c.SessionID != srcSession {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range targets {
		_ = c.Send(frame)
	}
}

// MACTableSnapshot returns a point-in-time copy of the MAC address table,
// joined with the current client list to resolve session IDs to logins.
func (h *Hub) MACTableSnapshot() []MACRecord {
	now := time.Now()
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]MACRecord, 0, len(h.macTable))
	for mac, e := range h.macTable {
		if now.After(e.expires) {
			continue // skip entries that have logically expired (purge runs async)
		}
		login := ""
		if c, ok := h.clients[e.sessionID]; ok {
			login = c.Login
		}
		rec := MACRecord{
			MAC:       net.HardwareAddr(mac[:]),
			SessionID: e.sessionID,
			Login:     login,
			ExpiresIn: e.expires.Sub(now).Truncate(time.Second),
		}
		if e.ip != nil {
			rec.IP = e.ip
		}
		out = append(out, rec)
	}
	return out
}

func cloneIP(b []byte) net.IP {
	cp := make(net.IP, len(b))
	copy(cp, b)
	return cp
}

func fmtMAC(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// ClientCount returns number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// purgeMACTable removes stale entries. Call periodically.
func (h *Hub) purgeMACTable() {
	now := time.Now()
	h.mu.Lock()
	for mac, e := range h.macTable {
		if now.After(e.expires) {
			delete(h.macTable, mac)
		}
	}
	h.mu.Unlock()
}

// StartMACPurge runs a background goroutine that purges stale MAC table entries
// every minute. It stops when ctx is cancelled.
func (h *Hub) StartMACPurge(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.purgeMACTable()
			}
		}
	}()
}

// Manager holds a set of hubs indexed by ID.
type Manager struct {
	mu   sync.RWMutex
	hubs map[uint16]*Hub
}

// NewManager creates an empty Manager.
func NewManager() *Manager {
	return &Manager{hubs: make(map[uint16]*Hub)}
}

// Add registers a hub with the manager. Overwrites any existing hub with the same ID.
func (m *Manager) Add(h *Hub) {
	m.mu.Lock()
	m.hubs[h.id] = h
	m.mu.Unlock()
}

// Get looks up a hub by ID.
func (m *Manager) Get(id uint16) (*Hub, bool) {
	m.mu.RLock()
	h, ok := m.hubs[id]
	m.mu.RUnlock()
	return h, ok
}

// List returns all registered hubs in an unspecified order.
func (m *Manager) List() []*Hub {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Hub, 0, len(m.hubs))
	for _, h := range m.hubs {
		out = append(out, h)
	}
	return out
}
