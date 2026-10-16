//go:build windows && amd64

package divert

import (
	"testing"
	"unsafe"
)

func TestWinDivertABILayout(t *testing.T) {
	// 1. Structure size verification:
	// WINDIVERT_ADDRESS in WinDivert 2.2.2 is exactly 80 bytes:
	// INT64 Timestamp (8) + UINT32 bitfields (4) + UINT32 Reserved2 (4) + 64-byte union = 80 bytes.
	var addr Address
	if size := unsafe.Sizeof(addr); size != AddressSize {
		t.Fatalf("sizeof(WINDIVERT_ADDRESS) mismatch: got %d bytes, want %d bytes", size, AddressSize)
	}
	if unsafe.Sizeof(addr.Data) != AddressUnionSize {
		t.Fatalf("sizeof(Address.Data union storage) = %d, want %d", unsafe.Sizeof(addr.Data), AddressUnionSize)
	}

	// 2. Field offset verification in WINDIVERT_ADDRESS:
	if off := unsafe.Offsetof(addr.Timestamp); off != 0 {
		t.Fatalf("offset(Timestamp) = %d, want 0", off)
	}
	if off := unsafe.Offsetof(addr.Bits); off != 8 {
		t.Fatalf("offset(Bits) = %d, want 8", off)
	}
	if off := unsafe.Offsetof(addr.Reserved2); off != 12 {
		t.Fatalf("offset(Reserved2) = %d, want 12", off)
	}
	if off := unsafe.Offsetof(addr.Data); off != 16 {
		t.Fatalf("offset(Data) = %d, want 16", off)
	}

	// Alignment verification: Address starts on 8-byte boundary, and Data offset (16)
	// is an exact multiple of 8, satisfying alignment for union members containing uint64/int64.
	if align := unsafe.Alignof(addr); align != 8 {
		t.Fatalf("alignof(Address) = %d, want 8", align)
	}
	if off := unsafe.Offsetof(addr.Data); off%8 != 0 {
		t.Fatalf("offset(Data) = %d must be a multiple of 8 for 64-bit alignment", off)
	}

	// 3. Sub-structure size and offset verification:
	// A. WINDIVERT_DATA_NETWORK (declared C size: 8 bytes, alignment: 4 bytes).
	// Confirms: contains ONLY IfIdx and SubIfIdx. No Direction field.
	var netData DataNetwork
	if size := unsafe.Sizeof(netData); size != DataNetworkSize {
		t.Fatalf("sizeof(WINDIVERT_DATA_NETWORK) mismatch: got %d bytes, want %d bytes", size, DataNetworkSize)
	}
	if off := unsafe.Offsetof(netData.IfIdx); off != 0 {
		t.Fatalf("offset(DataNetwork.IfIdx) = %d, want 0", off)
	}
	if off := unsafe.Offsetof(netData.SubIfIdx); off != 4 {
		t.Fatalf("offset(DataNetwork.SubIfIdx) = %d, want 4", off)
	}
	if align := unsafe.Alignof(netData); align != 4 {
		t.Fatalf("alignof(DataNetwork) = %d, want 4", align)
	}

	// B. WINDIVERT_DATA_FLOW (declared C size: 64 bytes, alignment: 8 bytes).
	var flowData DataFlow
	if size := unsafe.Sizeof(flowData); size != DataFlowSize {
		t.Fatalf("sizeof(WINDIVERT_DATA_FLOW) mismatch: got %d bytes, want %d bytes", size, DataFlowSize)
	}
	if off := unsafe.Offsetof(flowData.EndpointID); off != 0 {
		t.Fatalf("offset(DataFlow.EndpointID) = %d, want 0", off)
	}
	if off := unsafe.Offsetof(flowData.ParentEndpointID); off != 8 {
		t.Fatalf("offset(DataFlow.ParentEndpointID) = %d, want 8", off)
	}
	if off := unsafe.Offsetof(flowData.ProcessID); off != 16 {
		t.Fatalf("offset(DataFlow.ProcessID) = %d, want 16", off)
	}
	if off := unsafe.Offsetof(flowData.LocalAddr); off != 20 {
		t.Fatalf("offset(DataFlow.LocalAddr) = %d, want 20", off)
	}
	if off := unsafe.Offsetof(flowData.RemoteAddr); off != 36 {
		t.Fatalf("offset(DataFlow.RemoteAddr) = %d, want 36", off)
	}
	if off := unsafe.Offsetof(flowData.LocalPort); off != 52 {
		t.Fatalf("offset(DataFlow.LocalPort) = %d, want 52", off)
	}
	if off := unsafe.Offsetof(flowData.RemotePort); off != 54 {
		t.Fatalf("offset(DataFlow.RemotePort) = %d, want 54", off)
	}
	if off := unsafe.Offsetof(flowData.Protocol); off != 56 {
		t.Fatalf("offset(DataFlow.Protocol) = %d, want 56", off)
	}
	if align := unsafe.Alignof(flowData); align != 8 {
		t.Fatalf("alignof(DataFlow) = %d, want 8", align)
	}

	// C. WINDIVERT_DATA_SOCKET (declared C size: 64 bytes, alignment: 8 bytes).
	var socketData DataSocket
	if size := unsafe.Sizeof(socketData); size != DataSocketSize {
		t.Fatalf("sizeof(WINDIVERT_DATA_SOCKET) mismatch: got %d bytes, want %d bytes", size, DataSocketSize)
	}
	if off := unsafe.Offsetof(socketData.EndpointID); off != 0 {
		t.Fatalf("offset(DataSocket.EndpointID) = %d, want 0", off)
	}
	if off := unsafe.Offsetof(socketData.ParentEndpointID); off != 8 {
		t.Fatalf("offset(DataSocket.ParentEndpointID) = %d, want 8", off)
	}
	if off := unsafe.Offsetof(socketData.ProcessID); off != 16 {
		t.Fatalf("offset(DataSocket.ProcessID) = %d, want 16", off)
	}
	if off := unsafe.Offsetof(socketData.LocalAddr); off != 20 {
		t.Fatalf("offset(DataSocket.LocalAddr) = %d, want 20", off)
	}
	if off := unsafe.Offsetof(socketData.RemoteAddr); off != 36 {
		t.Fatalf("offset(DataSocket.RemoteAddr) = %d, want 36", off)
	}
	if off := unsafe.Offsetof(socketData.LocalPort); off != 52 {
		t.Fatalf("offset(DataSocket.LocalPort) = %d, want 52", off)
	}
	if off := unsafe.Offsetof(socketData.RemotePort); off != 54 {
		t.Fatalf("offset(DataSocket.RemotePort) = %d, want 54", off)
	}
	if off := unsafe.Offsetof(socketData.Protocol); off != 56 {
		t.Fatalf("offset(DataSocket.Protocol) = %d, want 56", off)
	}
	if align := unsafe.Alignof(socketData); align != 8 {
		t.Fatalf("alignof(DataSocket) = %d, want 8", align)
	}

	// D. WINDIVERT_DATA_REFLECT (declared C size: 32 bytes, alignment: 8 bytes).
	// Under Windows x64 ABI: Timestamp (8) + ProcessID (4) + Layer (4) + Flags (8) + Priority (2) + 6B pad = 32 bytes.
	var reflectData DataReflect
	if size := unsafe.Sizeof(reflectData); size != DataReflectSize {
		t.Fatalf("sizeof(WINDIVERT_DATA_REFLECT) mismatch: got %d bytes, want %d bytes", size, DataReflectSize)
	}
	if off := unsafe.Offsetof(reflectData.Timestamp); off != 0 {
		t.Fatalf("offset(DataReflect.Timestamp) = %d, want 0", off)
	}
	if off := unsafe.Offsetof(reflectData.ProcessID); off != 8 {
		t.Fatalf("offset(DataReflect.ProcessID) = %d, want 8", off)
	}
	if off := unsafe.Offsetof(reflectData.Layer); off != 12 {
		t.Fatalf("offset(DataReflect.Layer) = %d, want 12", off)
	}
	if off := unsafe.Offsetof(reflectData.Flags); off != 16 {
		t.Fatalf("offset(DataReflect.Flags) = %d, want 16", off)
	}
	if off := unsafe.Offsetof(reflectData.Priority); off != 24 {
		t.Fatalf("offset(DataReflect.Priority) = %d, want 24", off)
	}
	if align := unsafe.Alignof(reflectData); align != 8 {
		t.Fatalf("alignof(DataReflect) = %d, want 8", align)
	}

	// 4. Distinguish C member structure sizes from 64-byte union storage:
	// In WINDIVERT_ADDRESS, the union is:
	// union { DataNetwork; DataFlow; DataSocket; DataReflect; UINT8 Reserved3[64]; };
	// Therefore the union storage is always 64 bytes, even though individual member structures
	// are 8 bytes (Network) or 32 bytes (Reflect).
	if DataNetworkSize >= AddressUnionSize {
		t.Fatalf("DataNetworkSize (%d) must be strictly smaller than AddressUnionSize (%d)", DataNetworkSize, AddressUnionSize)
	}
	if DataReflectSize >= AddressUnionSize {
		t.Fatalf("DataReflectSize (%d) must be strictly smaller than AddressUnionSize (%d)", DataReflectSize, AddressUnionSize)
	}
	if DataFlowSize != AddressUnionSize {
		t.Fatalf("DataFlowSize (%d) must match AddressUnionSize (%d)", DataFlowSize, AddressUnionSize)
	}
	if DataSocketSize != AddressUnionSize {
		t.Fatalf("DataSocketSize (%d) must match AddressUnionSize (%d)", DataSocketSize, AddressUnionSize)
	}
}

func TestWinDivertAddressBitfields(t *testing.T) {
	var addr Address

	// 1. Bitfield isolation test: verify each bit individually without corrupting adjacent bits.
	bitTests := []struct {
		name     string
		set      func(v bool)
		get      func() bool
		expected uint32
	}{
		{"Sniffed", addr.SetSniffed, addr.Sniffed, bitSniffed},
		{"Outbound", addr.SetOutbound, addr.Outbound, bitOutbound},
		{"Loopback", addr.SetLoopback, addr.Loopback, bitLoopback},
		{"Impostor", addr.SetImpostor, addr.Impostor, bitImpostor},
		{"IPv6", addr.SetIPv6, addr.IPv6, bitIPv6},
		{"IPChecksum", addr.SetIPChecksum, addr.IPChecksum, bitIPChecksum},
		{"TCPChecksum", addr.SetTCPChecksum, addr.TCPChecksum, bitTCPChecksum},
		{"UDPChecksum", addr.SetUDPChecksum, addr.UDPChecksum, bitUDPChecksum},
	}

	for _, bt := range bitTests {
		addr.Bits = 0
		if bt.get() {
			t.Fatalf("%s: expected false initially", bt.name)
		}
		bt.set(true)
		if !bt.get() {
			t.Fatalf("%s: expected true after set(true)", bt.name)
		}
		if addr.Bits != bt.expected {
			t.Fatalf("%s: raw Bits = 0x%08x, want 0x%08x", bt.name, addr.Bits, bt.expected)
		}
		bt.set(false)
		if bt.get() {
			t.Fatalf("%s: expected false after set(false)", bt.name)
		}
		if addr.Bits != 0 {
			t.Fatalf("%s: raw Bits = 0x%08x after clear, want 0", bt.name, addr.Bits)
		}
	}

	// 2. Multi-bit fields isolation:
	// Layer (bits 0..7)
	layerValues := []uint8{0, 1, 2, 3, 4, 127, 255}
	for _, lv := range layerValues {
		addr.Bits = 0
		addr.SetLayer(lv)
		if addr.Layer() != lv {
			t.Fatalf("Layer roundtrip failed: got %d, want %d", addr.Layer(), lv)
		}
		if addr.Bits != uint32(lv) {
			t.Fatalf("Layer leaked into other bitfield positions: raw Bits = 0x%08x, want 0x%08x", addr.Bits, uint32(lv))
		}
	}

	// Event (bits 8..15)
	eventValues := []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 128, 255}
	for _, ev := range eventValues {
		addr.Bits = 0
		addr.SetEvent(ev)
		if addr.Event() != ev {
			t.Fatalf("Event roundtrip failed: got %d, want %d", addr.Event(), ev)
		}
		if addr.Bits != (uint32(ev) << shiftEvent) {
			t.Fatalf("Event leaked into other bitfield positions: raw Bits = 0x%08x, want 0x%08x", addr.Bits, uint32(ev)<<shiftEvent)
		}
	}

	// Reserved1 (bits 24..31)
	res1Values := []uint8{0, 1, 0x55, 0xAA, 0xFF}
	for _, rv := range res1Values {
		addr.Bits = 0
		addr.SetReserved1(rv)
		if addr.Reserved1() != rv {
			t.Fatalf("Reserved1 roundtrip failed: got %d, want %d", addr.Reserved1(), rv)
		}
		if addr.Bits != (uint32(rv) << 24) {
			t.Fatalf("Reserved1 leaked into other bitfield positions: raw Bits = 0x%08x, want 0x%08x", addr.Bits, uint32(rv)<<24)
		}
	}

	// 3. Combined composite bitfield verification:
	addr.Bits = 0
	addr.SetLayer(uint8(LayerSocket)) // 3
	addr.SetEvent(EventSocketConnect) // 4
	addr.SetSniffed(true)             // bit 16
	addr.SetOutbound(true)            // bit 17
	addr.SetLoopback(false)           // bit 18
	addr.SetImpostor(true)            // bit 19
	addr.SetIPv6(true)                // bit 20
	addr.SetIPChecksum(false)         // bit 21
	addr.SetTCPChecksum(true)         // bit 22
	addr.SetUDPChecksum(false)        // bit 23
	addr.SetReserved1(0xFE)           // bits 24..31

	expectedBits := uint32(3) | (uint32(4) << 8) | bitSniffed | bitOutbound | bitImpostor | bitIPv6 | bitTCPChecksum | (uint32(0xFE) << 24)
	if addr.Bits != expectedBits {
		t.Fatalf("Composite Bits = 0x%08x, want 0x%08x", addr.Bits, expectedBits)
	}

	if addr.Layer() != uint8(LayerSocket) || addr.Event() != EventSocketConnect ||
		!addr.Sniffed() || !addr.Outbound() || addr.Loopback() || !addr.Impostor() ||
		!addr.IPv6() || addr.IPChecksum() || !addr.TCPChecksum() || addr.UDPChecksum() ||
		addr.Reserved1() != 0xFE {
		t.Fatal("Composite bitfield field getters returned inconsistent values")
	}

	// 4. Direction metadata placement assertion:
	// Verify that Direction is represented in Address.Outbound, NOT in DataNetwork.
	addr.SetOutbound(true)
	if !addr.Outbound() {
		t.Fatal("Direction metadata (Outbound) must be set on Address")
	}
}

func TestWinDivertUnionAccessors(t *testing.T) {
	var addr Address

	// A. DataNetwork accessor roundtrip and padding zeroing:
	addr.Data = [64]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEE, 0xEE}
	addr.SetNetwork(DataNetwork{IfIdx: 42, SubIfIdx: 7})
	net := addr.Network()
	if net.IfIdx != 42 || net.SubIfIdx != 7 {
		t.Fatalf("DataNetwork roundtrip failed: got (%d, %d), want (42, 7)", net.IfIdx, net.SubIfIdx)
	}
	// Verify bytes 8..63 were cleanly zeroed
	for i := 8; i < 64; i++ {
		if addr.Data[i] != 0 {
			t.Fatalf("SetNetwork failed to zero union padding at byte %d (got 0x%02x)", i, addr.Data[i])
		}
	}

	// B. DataFlow accessor roundtrip:
	flowInput := DataFlow{
		EndpointID:       0x0102030405060708,
		ParentEndpointID: 0x0807060504030201,
		ProcessID:        1234,
		LocalAddr:        [4]uint32{0x7F000001, 0, 0, 0},
		RemoteAddr:       [4]uint32{0x7F000001, 0, 0, 0},
		LocalPort:        54321,
		RemotePort:       12345,
		Protocol:         6,
	}
	addr.SetFlow(flowInput)
	flowOutput := addr.Flow()
	if flowOutput.EndpointID != flowInput.EndpointID ||
		flowOutput.ParentEndpointID != flowInput.ParentEndpointID ||
		flowOutput.ProcessID != flowInput.ProcessID ||
		flowOutput.LocalAddr != flowInput.LocalAddr ||
		flowOutput.RemoteAddr != flowInput.RemoteAddr ||
		flowOutput.LocalPort != flowInput.LocalPort ||
		flowOutput.RemotePort != flowInput.RemotePort ||
		flowOutput.Protocol != flowInput.Protocol {
		t.Fatalf("DataFlow roundtrip mismatch: got %+v, want %+v", flowOutput, flowInput)
	}

	// C. DataSocket accessor roundtrip:
	sockInput := DataSocket{
		EndpointID:       0xAAAAAAAAAAAAAAAA,
		ParentEndpointID: 0xBBBBBBBBBBBBBBBB,
		ProcessID:        5678,
		LocalAddr:        [4]uint32{0x0A000001, 0, 0, 0},
		RemoteAddr:       [4]uint32{0x0A000002, 0, 0, 0},
		LocalPort:        8080,
		RemotePort:       443,
		Protocol:         6,
	}
	addr.SetSocket(sockInput)
	sockOutput := addr.Socket()
	if sockOutput.EndpointID != sockInput.EndpointID ||
		sockOutput.ParentEndpointID != sockInput.ParentEndpointID ||
		sockOutput.ProcessID != sockInput.ProcessID ||
		sockOutput.LocalAddr != sockInput.LocalAddr ||
		sockOutput.RemoteAddr != sockInput.RemoteAddr ||
		sockOutput.LocalPort != sockInput.LocalPort ||
		sockOutput.RemotePort != sockInput.RemotePort ||
		sockOutput.Protocol != sockInput.Protocol {
		t.Fatalf("DataSocket roundtrip mismatch: got %+v, want %+v", sockOutput, sockInput)
	}

	// D. DataReflect accessor roundtrip and padding zeroing:
	for i := range addr.Data {
		addr.Data[i] = 0xCC
	}
	reflectInput := DataReflect{
		Timestamp: 987654321,
		ProcessID: 4321,
		Layer:     LayerReflect,
		Flags:     FlagSniff | FlagDrop,
		Priority:  1000,
	}
	addr.SetReflect(reflectInput)
	reflectOutput := addr.Reflect()
	if reflectOutput.Timestamp != reflectInput.Timestamp ||
		reflectOutput.ProcessID != reflectInput.ProcessID ||
		reflectOutput.Layer != reflectInput.Layer ||
		reflectOutput.Flags != reflectInput.Flags ||
		reflectOutput.Priority != reflectInput.Priority {
		t.Fatalf("DataReflect roundtrip mismatch: got %+v, want %+v", reflectOutput, reflectInput)
	}
	// Verify bytes 32..63 were cleanly zeroed
	for i := 32; i < 64; i++ {
		if addr.Data[i] != 0 {
			t.Fatalf("SetReflect failed to zero trailing union padding at byte %d (got 0x%02x)", i, addr.Data[i])
		}
	}
}

func TestWinDivertConstants(t *testing.T) {
	// Validate upstream constant values from windivert.h 2.2.2
	if LayerNetwork != 0 || LayerNetworkForward != 1 || LayerFlow != 2 || LayerSocket != 3 || LayerReflect != 4 {
		t.Fatal("Layer constants mismatch with upstream windivert.h")
	}

	if EventNetworkPacket != 0 || EventFlowEstablished != 1 || EventFlowDeleted != 2 ||
		EventSocketBind != 3 || EventSocketConnect != 4 || EventSocketListen != 5 ||
		EventSocketAccept != 6 || EventSocketClose != 7 || EventReflectOpen != 8 || EventReflectClose != 9 {
		t.Fatal("Event constants mismatch with upstream windivert.h")
	}

	if FlagSniff != 0x0001 || FlagDrop != 0x0002 || FlagRecvOnly != 0x0004 || FlagSendOnly != 0x0008 ||
		FlagNoInstall != 0x0010 || FlagFragments != 0x0020 {
		t.Fatal("Flag constants mismatch with upstream windivert.h")
	}

	if PriorityHighest != 30000 || PriorityLowest != -30000 {
		t.Fatal("Priority constants mismatch with upstream windivert.h")
	}

	if ParamQueueLength != 0 || ParamQueueTime != 1 || ParamQueueSize != 2 ||
		ParamVersionMajor != 3 || ParamVersionMinor != 4 {
		t.Fatal("Param constants mismatch with upstream windivert.h")
	}

	if ShutdownRecv != 1 || ShutdownSend != 2 || ShutdownBoth != 3 {
		t.Fatal("Shutdown constants mismatch with upstream windivert.h")
	}

	expectedFilter := "loopback and outbound and !impostor and ip.DstAddr == 127.0.0.1 and tcp.DstPort == 54321 and tcp.PayloadLength > 0"
	if FilterLoopbackTest != expectedFilter {
		t.Fatalf("FilterLoopbackTest mismatch: got %q, want %q", FilterLoopbackTest, expectedFilter)
	}

	if LoopbackTestPort != 54321 {
		t.Fatalf("LoopbackTestPort mismatch: got %d, want 54321", LoopbackTestPort)
	}
}

func TestWinDivertDLLNotLoadedInOfflineTests(t *testing.T) {
	// Structural verification: compiling, importing, and testing this package
	// must NOT load WinDivert.dll or touch the Windows driver subsystem.
	if IsDLLLoaded() {
		t.Fatal("VIOLATION: WinDivert.dll is loaded during offline tests!")
	}
}

func TestWinDivertAddressRawPointerAndReserved(t *testing.T) {
	var addr Address
	addr.Reserved2 = 0xDEADBEEF
	if addr.Reserved2 != 0xDEADBEEF {
		t.Fatalf("Reserved2 mismatch: got 0x%08x, want 0xDEADBEEF", addr.Reserved2)
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
}
