package ngnet

import (
	"errors"
	"net"
	"sync"

	zlog "github.com/rs/zerolog/log"
)

// The listener registry owns process-wide net.Listeners keyed by address, so
// service generations hand a port over instead of closing and rebinding it.
//
// Acquire pushes a handler onto the address's holder stack; the newest holder
// receives connections. Releasing pops the holder and connections fall back
// to the previous one — so when a failed reload retires its half-built
// generation, the port returns to the still-running generation with no gap.
// The listener is closed only when the last holder releases it.

type listenerHolder struct {
	handler func(net.Conn)
}

type listenerEntry struct {
	listener net.Listener
	stack    []*listenerHolder
}

type listenerRegistry struct {
	mu      sync.Mutex
	entries map[string]*listenerEntry
}

func newListenerRegistry() *listenerRegistry {
	return &listenerRegistry{entries: map[string]*listenerEntry{}}
}

// Acquire makes handler the active receiver for connections on address,
// creating the listener if no generation holds it yet. The returned release
// is idempotent; calling it hands the address back to the previous holder,
// closing the listener when none remains.
func (r *listenerRegistry) Acquire(network, address string, handler func(net.Conn)) (release func(), err error) {
	key := network + "/" + address

	r.mu.Lock()
	defer r.mu.Unlock()

	ent, ok := r.entries[key]
	if !ok {
		l, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		ent = &listenerEntry{listener: l}
		r.entries[key] = ent
		go r.serve(key, ent)
	}

	holder := &listenerHolder{handler: handler}
	ent.stack = append(ent.stack, holder)

	var once sync.Once
	return func() {
		once.Do(func() { r.release(key, holder) })
	}, nil
}

func (r *listenerRegistry) serve(key string, ent *listenerEntry) {
	defer func() {
		r.mu.Lock()
		if r.entries[key] == ent {
			delete(r.entries, key)
		}
		r.mu.Unlock()
		ent.listener.Close()
	}()

	for {
		conn, err := ent.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				zlog.Error().Str("type", "net/listen").Str("addr", key).Err(err).Msg("accept failed")
			}
			return
		}

		r.mu.Lock()
		var handler func(net.Conn)
		if n := len(ent.stack); n > 0 {
			handler = ent.stack[n-1].handler
		}
		r.mu.Unlock()

		if handler == nil {
			conn.Close()
			continue
		}
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					zlog.Error().Str("type", "net/listen").Str("addr", key).
						Interface("err", rec).Msg("connection handler panic")
					conn.Close()
				}
			}()
			handler(conn)
		}()
	}
}

func (r *listenerRegistry) release(key string, holder *listenerHolder) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ent, ok := r.entries[key]
	if !ok {
		return
	}
	for i, h := range ent.stack {
		if h == holder {
			ent.stack = append(ent.stack[:i], ent.stack[i+1:]...)
			break
		}
	}
	if len(ent.stack) == 0 {
		delete(r.entries, key)
		ent.listener.Close()
	}
}

var defaultListeners = newListenerRegistry()

// AcquireListener acquires address on the process-wide listener registry.
// See listenerRegistry.Acquire for the handoff semantics.
func AcquireListener(network, address string, handler func(net.Conn)) (release func(), err error) {
	return defaultListeners.Acquire(network, address, handler)
}
