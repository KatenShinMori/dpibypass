//go:build !(windows && amd64)

package divert

import (
	"testing"
	"unsafe"
)

func TestWinDivertStub_AddressAndConstants(t *testing.T) {
	if IsDLLLoaded() {
		t.Fatal("IsDLLLoaded must return false on non-Windows")
	}

	var addr Address
	addr.Reserved2 = 0x12345678
	if addr.Reserved2 != 0x12345678 {
		t.Fatalf("Reserved2 mismatch: got 0x%08x", addr.Reserved2)
	}

	addr.SetNetwork(DataNetwork{IfIdx: 10, SubIfIdx: 20})
	net := addr.Network()
	if net.IfIdx != 10 || net.SubIfIdx != 20 {
		t.Fatalf("Network roundtrip failed: %+v", net)
	}

	flowIn := DataFlow{EndpointID: 100, ProcessID: 200, Protocol: 6}
	addr.SetFlow(flowIn)
	flowOut := addr.Flow()
	if flowOut.EndpointID != 100 || flowOut.ProcessID != 200 || flowOut.Protocol != 6 {
		t.Fatalf("Flow roundtrip failed: %+v", flowOut)
	}

	sockIn := DataSocket{EndpointID: 300, ProcessID: 400, Protocol: 17}
	addr.SetSocket(sockIn)
	sockOut := addr.Socket()
	if sockOut.EndpointID != 300 || sockOut.ProcessID != 400 || sockOut.Protocol != 17 {
		t.Fatalf("Socket roundtrip failed: %+v", sockOut)
	}

	refIn := DataReflect{Timestamp: 500, ProcessID: 600, Layer: LayerReflect}
	addr.SetReflect(refIn)
	refOut := addr.Reflect()
	if refOut.Timestamp != 500 || refOut.ProcessID != 600 || refOut.Layer != LayerReflect {
		t.Fatalf("Reflect roundtrip failed: %+v", refOut)
	}

	raw := addr.RawPointer()
	if raw == nil {
		t.Fatal("RawPointer() returned nil for non-nil address")
	}
	if raw != unsafe.Pointer(&addr) {
		t.Fatalf("RawPointer() pointer address mismatch: got %p, want %p", raw, &addr)
	}

	var nilAddr *Address
	if nilAddr.RawPointer() != nil {
		t.Fatal("RawPointer() must return nil for nil Address pointer")
	}

	// Verify unsupported platform errors
	if _, err := Open("true", 0, 0, 0); err != ErrUnsupportedPlatform {
		t.Fatalf("Open want ErrUnsupportedPlatform, got %v", err)
	}
	if _, err := Recv(InvalidHandle, make([]byte, 100), &addr); err != ErrUnsupportedPlatform {
		t.Fatalf("Recv want ErrUnsupportedPlatform, got %v", err)
	}
	if _, err := Send(InvalidHandle, make([]byte, 100), &addr); err != ErrUnsupportedPlatform {
		t.Fatalf("Send want ErrUnsupportedPlatform, got %v", err)
	}
	if err := Close(InvalidHandle); err != ErrUnsupportedPlatform {
		t.Fatalf("Close want ErrUnsupportedPlatform, got %v", err)
	}
}
