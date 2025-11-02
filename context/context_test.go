package context

import (
	"testing"
)

func BenchmarkSignalContext_1Slot(b *testing.B) {
	ctx := &SignalContext{}
	slot := ctx.Slot("test")
	go func() {
		for {
			<-slot.Wait()
		}
	}()
	for n := 0; n < b.N; n++ {
		ctx.Signal("test", "test")
	}
}
func BenchmarkSignalContext_5Slot(b *testing.B) {
	ctx := &SignalContext{}
	slot1 := ctx.Slot("test")
	slot2 := ctx.Slot("test")
	slot3 := ctx.Slot("test")
	slot4 := ctx.Slot("test")
	slot5 := ctx.Slot("test")

	go func() {
		for {
			<-slot1.Wait()
		}
	}()
	go func() {
		for {
			<-slot2.Wait()
		}
	}()
	go func() {
		for {
			<-slot3.Wait()
		}
	}()
	go func() {
		for {
			<-slot4.Wait()
		}
	}()
	go func() {
		for {
			<-slot5.Wait()
		}
	}()

	for n := 0; n < b.N; n++ {
		ctx.Signal("test", "test")
	}
}

func BenchmarkStoreContextReadWith100Objs(b *testing.B) {
	ctx := &StoreContext{}
	for i := 0; i < 100; i++ {
		ctx.Store(i, i)
	}
	for n := 0; n < b.N; n++ {
		for i := 0; i < 100; i++ {
			ctx.Load(i)
		}
	}
}
func BenchmarkStoreContextWrite(b *testing.B) {
	ctx := &StoreContext{}
	for n := 0; n < b.N; n++ {
		ctx.Store(n, n)
	}
}
