package utils

import "sync"

type LookupFunc func(string) interface{}

type BufferedLookup struct {
	lookupFunc LookupFunc
	buff       map[string]interface{}
	lock       sync.RWMutex
}

func NewBufferedLookup(f LookupFunc) *BufferedLookup {
	return &BufferedLookup{
		lookupFunc: f,
		buff:       map[string]interface{}{},
	}
}

func (bl *BufferedLookup) Lookup(id string) (index interface{}) {
	bl.lock.RLock()
	index, ok := bl.buff[id]
	bl.lock.RUnlock()
	if ok {
		return
	}
	index = bl.lookupFunc(id)
	bl.lock.Lock()
	bl.buff[id] = index
	bl.lock.Unlock()
	return

}

func (bl *BufferedLookup) Refresh() {
	bl.lock.Lock()
	bl.buff = make(map[string]interface{})
	bl.lock.Unlock()
}
