package context

import (
	"errors"
	"sync"
)

type Context interface {
	Signal(interface{}, interface{}) error
	Slot(interface{}) ContextSlot
	Store(interface{}, interface{})
	Load(interface{}) (interface{}, bool)

	Close()
}
type ContextSlot interface {
	Wait() <-chan interface{}
	Close()
}
type StoreContext struct {
	sync.Map
}

func (ctx *StoreContext) Store(k interface{}, v interface{}) {
	ctx.Map.Store(k, v)
}
func (ctx *StoreContext) Load(k interface{}) (interface{}, bool) {
	return ctx.Map.Load(k)
}
func (ctx *StoreContext) NilLoad(k interface{}) interface{} {
	t, _ := ctx.Map.Load(k)
	return t
}

type SignalContext struct {
	mu        sync.RWMutex
	sigawaits map[interface{}]*slotmap

	i sync.Once
	c sync.Once

	closed bool
}
type slotmap struct {
	m  map[*chan interface{}]struct{}
	mu sync.RWMutex
}

func (ctx *SignalContext) init() {
	ctx.mu.Lock()
	if ctx.sigawaits == nil {
		ctx.sigawaits = make(map[interface{}]*slotmap)
	}
	ctx.mu.Unlock()
}

func (ctx *SignalContext) Signal(key interface{}, val interface{}) error {
	ctx.i.Do(ctx.init)

	ctx.mu.RLock()
	sm, ok := ctx.sigawaits[key]
	ctx.mu.RUnlock()

	if !ok {
		return errors.New("not any slot")
	}

	var t_m = []*chan interface{}{}
	sm.mu.RLock()
	for _chan := range sm.m {
		t_m = append(t_m, _chan)
	}
	sm.mu.RUnlock()
	defer func() { recover() }()
	for _, _chan := range t_m {
		*_chan <- val
	}
	return nil

}
func (ctx *SignalContext) Slot(key interface{}) ContextSlot {
	ctx.i.Do(ctx.init)

	var await = make(chan interface{})

	ctx.mu.Lock()

	if ctx.closed {
		ctx.mu.Unlock()
		return nilContextSlot{}
	}

	_map, ok := ctx.sigawaits[key]

	if !ok {
		_map = &slotmap{
			m:  map[*chan interface{}]struct{}{},
			mu: sync.RWMutex{},
		}
		ctx.sigawaits[key] = _map
	}
	ctx.mu.Unlock()

	_map.mu.Lock()
	_map.m[&await] = struct{}{}
	_map.mu.Unlock()
	return &SignalContextSlot{
		slot: &await,
		mmv:  _map,
	}
}

func (ctx *SignalContext) Close() {
	ctx.c.Do(func() {
		ctx.mu.Lock()
		ctx.closed = true
		for _, _cm := range ctx.sigawaits {
			_cm.mu.Lock()
			for k := range _cm.m {
				close(*k)
			}
			_cm.mu.Unlock()
		}
		ctx.mu.Unlock()
	})
}

type SignalContextSlot struct {
	slot *chan interface{}
	mmv  *slotmap
}

func (slt *SignalContextSlot) Wait() <-chan interface{} {
	return *slt.slot
}
func (slt *SignalContextSlot) Close() {
	slt.mmv.mu.Lock()
	delete(slt.mmv.m, slt.slot)
	slt.mmv.mu.Unlock()

	close(*slt.slot)

}

type NilContext struct {
}
type nilContextSlot struct {
}

func (nilContextSlot) Wait() <-chan interface{} {
	return closedchan
}
func (nilContextSlot) Close() {

}
func (ctx NilContext) Signal(key interface{}, val interface{}) {
}
func (ctx NilContext) Slot(interface{}) ContextSlot {
	return &nilContextSlot{}
}

func (NilContext) Store(k interface{}, v interface{}) {}
func (NilContext) Load(k interface{}) (interface{}, bool) {
	return nil, false
}
func (NilContext) Close() {}

type backgroundCtx struct {
	SignalContext
	StoreContext
}

var Background = backgroundCtx{}

const (
// SHUTDOWN backgroundJobs = iota + 1010
)

func init() {
	close(closedchan)
}

var closedchan = make(chan interface{})

type HangContext struct {
}
type hangContextSlot struct {
}

func (hangContextSlot) Wait() <-chan interface{} {
	return nil
}
func (hangContextSlot) Close() {

}
func (ctx HangContext) Signal(key interface{}, val interface{}) error {
	return nil
}

func (ctx HangContext) Slot(interface{}) ContextSlot {
	return &hangContextSlot{}
}

func (HangContext) Store(k interface{}, v interface{}) {}
func (HangContext) Load(k interface{}) (interface{}, bool) {
	return nil, false
}
func (HangContext) Close() {}
