package utils

import "sync"

type LookupFunc[T any] func(string) T

type BufferedLookup[T any] struct {
	lookupFunc LookupFunc[T]
	buff       map[string]T
	lock       sync.RWMutex
}

func NewBufferedLookup[T any](f LookupFunc[T]) *BufferedLookup[T] {
	return &BufferedLookup[T]{
		lookupFunc: f,
		buff:       make(map[string]T),
	}
}

func (bl *BufferedLookup[T]) Lookup(id string) T {
	bl.lock.RLock()
	value, ok := bl.buff[id]
	bl.lock.RUnlock()
	if ok {
		return value
	}
	value = bl.lookupFunc(id)
	bl.lock.Lock()
	bl.buff[id] = value
	bl.lock.Unlock()
	return value
}

func (bl *BufferedLookup[T]) Refresh() {
	bl.lock.Lock()
	bl.buff = make(map[string]T)
	bl.lock.Unlock()
}
