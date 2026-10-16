//go:build windows && amd64

package divert

import (
	"encoding/binary"
	"unsafe"
)

// WinDivert 2.2.2 ABI Constants (windivert.h).
const (
	// Layers (WINDIVERT_LAYER)
	LayerNetwork        uint32 = 0
	LayerNetworkForward uint32 = 1
	LayerFlow           uint32 = 2
	LayerSocket         uint32 = 3
	LayerReflect        uint32 = 4

	// Events (WINDIVERT_EVENT)
	EventNetworkPacket   uint8 = 0
	EventFlowEstablished uint8 = 1
	EventFlowDeleted     uint8 = 2
	EventSocketBind      uint8 = 3
	EventSocketConnect   uint8 = 4
	EventSocketListen    uint8 = 5
	EventSocketAccept    uint8 = 6
	EventSocketClose     uint8 = 7
	EventReflectOpen     uint8 = 8
	EventReflectClose    uint8 = 9

	// Flags (WINDIVERT_FLAG_*)
	FlagSniff     uint64 = 0x0001
	FlagDrop      uint64 = 0x0002
	FlagRecvOnly  uint64 = 0x0004
	FlagReadOnly  uint64 = 0x0004
	FlagSendOnly  uint64 = 0x0008
	FlagWriteOnly uint64 = 0x0008
	FlagNoInstall uint64 = 0x0010
	FlagFragments uint64 = 0x0020

	// Priorities
	PriorityHighest int16 = 30000
	PriorityLowest  int16 = -30000

	// Parameters (WINDIVERT_PARAM)
	ParamQueueLength  uint32 = 0
	ParamQueueTime    uint32 = 1
	ParamQueueSize    uint32 = 2
	ParamVersionMajor uint32 = 3
	ParamVersionMinor uint32 = 4

	// Shutdown (WINDIVERT_SHUTDOWN)
	ShutdownRecv uint32 = 0x1
	ShutdownSend uint32 = 0x2
	ShutdownBoth uint32 = 0x3

	// Queue defaults and limits
	ParamQueueLengthDefault = 4096
	ParamQueueLengthMin     = 32
	ParamQueueLengthMax     = 16384
	ParamQueueTimeDefault   = 2000 // 2s
	ParamQueueTimeMin       = 100  // 100ms
	ParamQueueTimeMax       = 16000
	ParamQueueSizeDefault   = 4194304 // 4MB
	ParamQueueSizeMin       = 65535
	ParamQueueSizeMax       = 33554432 // 32MB
	BatchMax                = 0xFF
	MTUMax                  = 40 + 0xFFFF

	// Offline Filter Specification (Documentation and Phase 2.1B Boundary).
	// Intended for future isolated loopback test only:
	// "loopback and outbound and !impostor and ip.DstAddr == 127.0.0.1 and tcp.DstPort == 54321 and tcp.PayloadLength > 0"
	FilterLoopbackTest = "loopback and outbound and !impostor and ip.DstAddr == 127.0.0.1 and tcp.DstPort == 54321 and tcp.PayloadLength > 0"
	LoopbackTestPort   = 54321

	// FilterOutboundProduction defines the tightly scoped WinDivert filter for outbound target traffic:
	// - Strictly excludes port 53 to prevent breaking unredirected DNS.
	// - Excludes DoH bootstrap IPs (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4) at the kernel filter level.
	// - Captures TCP traffic to ISP sinkhole 195.175.254.2 (including SYN) for immediate RST+ACK injection.
	// - Filters outbound non-loopback non-impostor TCP 80/443 (IPv4 payloads, IPv6 SYN/payloads) and UDP 443 (QUIC).
	FilterOutboundProduction = "outbound and !impostor and !loopback and ((ip and tcp and (ip.DstAddr == 195.175.254.2 or ((ip.DstAddr != 1.1.1.1 and ip.DstAddr != 1.0.0.1 and ip.DstAddr != 8.8.8.8 and ip.DstAddr != 8.8.4.4) and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.PayloadLength > 0))) or (ipv6 and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443) and (tcp.Syn or tcp.PayloadLength > 0)) or (udp and udp.DstPort == 443))"

	// FilterOutboundWithDNS defines the active filter when transparent DNS interception is enabled:
	// - Matches outbound UDP 53 even if impostor is true (capturing UDP-53 DNS packets re-injected by WFP filters such as Kaspersky).
	// - Excludes DoH bootstrap IPs (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4) on TCP 80/443 so DoH HTTPS requests are never self-intercepted.
	// - Captures TCP traffic to ISP sinkhole 195.175.254.2 (including SYN) for immediate RST+ACK injection.
	// - Filters outbound non-loopback non-impostor TCP 80/443 (IPv4 payloads, IPv6 SYN/payloads), TCP 53, and UDP 443 (QUIC).
	FilterOutboundWithDNS = "outbound and !loopback and ((udp and udp.DstPort == 53) or (!impostor and ((ip and tcp and (ip.DstAddr == 195.175.254.2 or tcp.DstPort == 53 or ((ip.DstAddr != 1.1.1.1 and ip.DstAddr != 1.0.0.1 and ip.DstAddr != 8.8.8.8 and ip.DstAddr != 8.8.4.4) and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.PayloadLength > 0))) or (ipv6 and tcp and (((tcp.DstPort == 80 or tcp.DstPort == 443) and (tcp.Syn or tcp.PayloadLength > 0)) or tcp.DstPort == 53)) or (udp and udp.DstPort == 443))))"

	// MaxPacketBufferSize is the required buffer size (65535 bytes = 64 KiB) for pre-allocated WinDivertRecv buffers,
	// accommodating Windows LSO/TSO multi-segment bursts and post-quantum TLS ClientHellos (X25519MLKEM768).
	MaxPacketBufferSize = 65535
)

// DataNetwork models WINDIVERT_DATA_NETWORK (declared C structure size: 8 bytes).
//
// In upstream windivert.h (v2.2.2):
//
//	typedef struct {
//	    UINT32 IfIdx;
//	    UINT32 SubIfIdx;
//	} WINDIVERT_DATA_NETWORK, *PWINDIVERT_DATA_NETWORK;
//
// Critical ABI notes:
//  1. The declared C structure size is exactly 8 bytes (IfIdx + SubIfIdx).
//  2. It does NOT contain a Direction field (in WinDivert 1.x, Direction was present;
//     in WinDivert 2.x, direction-related packet metadata is represented solely by the
//     Outbound bitfield in WINDIVERT_ADDRESS.Bits).
//  3. Inside WINDIVERT_ADDRESS, DataNetwork occupies the first 8 bytes of the 64-byte
//     union storage (Data); the remaining 56 bytes are union padding (Reserved3).
type DataNetwork struct {
	IfIdx    uint32
	SubIfIdx uint32
}

// DataFlow models WINDIVERT_DATA_FLOW (declared C structure size: 64 bytes).
//
// In upstream windivert.h (v2.2.2):
//
//	typedef struct {
//	    UINT64 EndpointId;
//	    UINT64 ParentEndpointId;
//	    UINT32 ProcessId;
//	    UINT32 LocalAddr[4];
//	    UINT32 RemoteAddr[4];
//	    UINT16 LocalPort;
//	    UINT16 RemotePort;
//	    UINT8  Protocol;
//	} WINDIVERT_DATA_FLOW, *PWINDIVERT_DATA_FLOW;
//
// Layout under Windows x64 ABI:
//   - EndpointId: offset 0 (8B)
//   - ParentEndpointId: offset 8 (8B)
//   - ProcessId: offset 16 (4B)
//   - LocalAddr: offset 20 (16B = 4*4B)
//   - RemoteAddr: offset 36 (16B = 4*4B)
//   - LocalPort: offset 52 (2B)
//   - RemotePort: offset 54 (2B)
//   - Protocol: offset 56 (1B)
//   - Tail alignment padding: 7 bytes (offset 57..63) to align struct to 8-byte boundary.
//
// Declared structure size is 64 bytes, completely filling the 64-byte union storage.
type DataFlow struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte // alignment padding to 64 bytes
}

// DataSocket models WINDIVERT_DATA_SOCKET (declared C structure size: 64 bytes).
//
// In upstream windivert.h (v2.2.2):
//
//	typedef struct {
//	    UINT64 EndpointId;
//	    UINT64 ParentEndpointId;
//	    UINT32 ProcessId;
//	    UINT32 LocalAddr[4];
//	    UINT32 RemoteAddr[4];
//	    UINT16 LocalPort;
//	    UINT16 RemotePort;
//	    UINT8  Protocol;
//	} WINDIVERT_DATA_SOCKET, *PWINDIVERT_DATA_SOCKET;
//
// Layout is identical to DataFlow: 57 bytes of fields + 7 bytes tail padding = 64 bytes,
// completely filling the 64-byte union storage.
type DataSocket struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte // alignment padding to 64 bytes
}

// DataReflect models WINDIVERT_DATA_REFLECT (declared C structure size: 32 bytes).
//
// In upstream windivert.h (v2.2.2):
//
//	typedef struct {
//	    INT64           Timestamp;
//	    UINT32          ProcessId;
//	    WINDIVERT_LAYER Layer;
//	    UINT64          Flags;
//	    INT16           Priority;
//	} WINDIVERT_DATA_REFLECT, *PWINDIVERT_DATA_REFLECT;
//
// Layout under Windows x64 ABI:
//   - Timestamp: offset 0 (8B, 8-byte aligned)
//   - ProcessId: offset 8 (4B, 4-byte aligned)
//   - Layer: offset 12 (4B, WINDIVERT_LAYER enum is 32-bit int)
//   - Flags: offset 16 (8B, 8-byte aligned)
//   - Priority: offset 24 (2B, 2-byte aligned)
//   - Tail alignment padding: 6 bytes (offset 26..31) for 8-byte struct alignment.
//
// Declared structure size is 32 bytes.
// Critical ABI note: In WINDIVERT_ADDRESS, DataReflect occupies the first 32 bytes of the
// 64-byte union storage (Data); the trailing 32 bytes are union storage padding (Reserved3).
type DataReflect struct {
	Timestamp int64
	ProcessID uint32
	Layer     uint32
	Flags     uint64
	Priority  int16
	_         [6]byte // alignment padding to 32 bytes
}

// Address models the 80-byte WINDIVERT_ADDRESS structure from windivert.h (v2.2.2).
//
// In C:
//
//	typedef struct {
//	    INT64  Timestamp;
//	    UINT32 Layer:8;
//	    UINT32 Event:8;
//	    UINT32 Sniffed:1;
//	    UINT32 Outbound:1;
//	    UINT32 Loopback:1;
//	    UINT32 Impostor:1;
//	    UINT32 IPv6:1;
//	    UINT32 IPChecksum:1;
//	    UINT32 TCPChecksum:1;
//	    UINT32 UDPChecksum:1;
//	    UINT32 Reserved1:8;
//	    UINT32 Reserved2;
//	    union {
//	        WINDIVERT_DATA_NETWORK Network;
//	        WINDIVERT_DATA_FLOW Flow;
//	        WINDIVERT_DATA_SOCKET Socket;
//	        WINDIVERT_DATA_REFLECT Reflect;
//	        UINT8 Reserved3[64];
//	    };
//	} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;
//
// Memory layout:
//   - Timestamp: offset 0 (8 bytes)
//   - Bits: offset 8 (4 bytes: Layer 8b, Event 8b, bitflags 8b, Reserved1 8b)
//   - Reserved2: offset 12 (4 bytes)
//   - Data: offset 16 (64 bytes: union storage sized to Reserved3[64])
//
// Total structure size is exactly 80 bytes.
type Address struct {
	Timestamp int64    // offset 0 (8 bytes)
	Bits      uint32   // offset 8 (4 bytes: Layer, Event, and bitfields)
	Reserved2 uint32   // offset 12 (4 bytes)
	Data      [64]byte // offset 16 (64 bytes: union payload)
}

// Structure size and union storage compile-time constants (windivert.h v2.2.2).
const (
	// AddressSize is the total size in bytes of WINDIVERT_ADDRESS (80 bytes).
	AddressSize = 80
	// AddressExpectedSize is retained for backwards compatibility.
	AddressExpectedSize = AddressSize
	// AddressUnionSize is the size in bytes of the union within WINDIVERT_ADDRESS (64 bytes).
	AddressUnionSize = 64

	// Declared C structure sizes under Windows x64 ABI:
	// DataNetworkSize: sizeof(WINDIVERT_DATA_NETWORK) = 8 bytes.
	DataNetworkSize = 8
	// DataFlowSize: sizeof(WINDIVERT_DATA_FLOW) = 64 bytes.
	DataFlowSize = 64
	// DataSocketSize: sizeof(WINDIVERT_DATA_SOCKET) = 64 bytes.
	DataSocketSize = 64
	// DataReflectSize: sizeof(WINDIVERT_DATA_REFLECT) = 32 bytes.
	DataReflectSize = 32
)

// Bitfield masks for Address.Bits
const (
	maskLayer      = 0x000000FF
	maskEvent      = 0x0000FF00
	shiftEvent     = 8
	bitSniffed     = 1 << 16
	bitOutbound    = 1 << 17
	bitLoopback    = 1 << 18
	bitImpostor    = 1 << 19
	bitIPv6        = 1 << 20
	bitIPChecksum  = 1 << 21
	bitTCPChecksum = 1 << 22
	bitUDPChecksum = 1 << 23
	maskReserved1  = 0xFF000000
)

// Accessor methods for bitfields in Address.Bits

func (a *Address) Layer() uint8 {
	return uint8(a.Bits & maskLayer)
}

func (a *Address) SetLayer(l uint8) {
	a.Bits = (a.Bits & ^uint32(maskLayer)) | uint32(l)
}

func (a *Address) Event() uint8 {
	return uint8((a.Bits & maskEvent) >> shiftEvent)
}

func (a *Address) SetEvent(e uint8) {
	a.Bits = (a.Bits & ^uint32(maskEvent)) | (uint32(e) << shiftEvent)
}

func (a *Address) Sniffed() bool {
	return (a.Bits & bitSniffed) != 0
}

func (a *Address) SetSniffed(v bool) {
	if v {
		a.Bits |= bitSniffed
	} else {
		a.Bits &^= bitSniffed
	}
}

func (a *Address) Outbound() bool {
	return (a.Bits & bitOutbound) != 0
}

func (a *Address) SetOutbound(v bool) {
	if v {
		a.Bits |= bitOutbound
	} else {
		a.Bits &^= bitOutbound
	}
}

func (a *Address) Loopback() bool {
	return (a.Bits & bitLoopback) != 0
}

func (a *Address) SetLoopback(v bool) {
	if v {
		a.Bits |= bitLoopback
	} else {
		a.Bits &^= bitLoopback
	}
}

func (a *Address) Impostor() bool {
	return (a.Bits & bitImpostor) != 0
}

func (a *Address) SetImpostor(v bool) {
	if v {
		a.Bits |= bitImpostor
	} else {
		a.Bits &^= bitImpostor
	}
}

func (a *Address) IPv6() bool {
	return (a.Bits & bitIPv6) != 0
}

func (a *Address) SetIPv6(v bool) {
	if v {
		a.Bits |= bitIPv6
	} else {
		a.Bits &^= bitIPv6
	}
}

func (a *Address) IPChecksum() bool {
	return (a.Bits & bitIPChecksum) != 0
}

func (a *Address) SetIPChecksum(v bool) {
	if v {
		a.Bits |= bitIPChecksum
	} else {
		a.Bits &^= bitIPChecksum
	}
}

func (a *Address) TCPChecksum() bool {
	return (a.Bits & bitTCPChecksum) != 0
}

func (a *Address) SetTCPChecksum(v bool) {
	if v {
		a.Bits |= bitTCPChecksum
	} else {
		a.Bits &^= bitTCPChecksum
	}
}

func (a *Address) UDPChecksum() bool {
	return (a.Bits & bitUDPChecksum) != 0
}

func (a *Address) SetUDPChecksum(v bool) {
	if v {
		a.Bits |= bitUDPChecksum
	} else {
		a.Bits &^= bitUDPChecksum
	}
}

func (a *Address) Reserved1() uint8 {
	return uint8((a.Bits & maskReserved1) >> 24)
}

func (a *Address) SetReserved1(r uint8) {
	a.Bits = (a.Bits & ^uint32(maskReserved1)) | (uint32(r) << 24)
}

// Network returns the DataNetwork view of Address.Data.
// WINDIVERT_DATA_NETWORK is 8 bytes; the remaining 56 bytes of Address.Data
// represent the unused portion of the 64-byte union storage (Reserved3).
func (a *Address) Network() DataNetwork {
	return DataNetwork{
		IfIdx:    binary.LittleEndian.Uint32(a.Data[0:4]),
		SubIfIdx: binary.LittleEndian.Uint32(a.Data[4:8]),
	}
}

// SetNetwork sets the DataNetwork fields into Address.Data.
// It zeroes the remaining 56 bytes of union storage to ensure clean union state.
func (a *Address) SetNetwork(n DataNetwork) {
	binary.LittleEndian.PutUint32(a.Data[0:4], n.IfIdx)
	binary.LittleEndian.PutUint32(a.Data[4:8], n.SubIfIdx)
	for i := 8; i < 64; i++ {
		a.Data[i] = 0
	}
}

// Flow returns the DataFlow view of Address.Data.
// Under Windows x64 ABI, DataFlow occupies the full 64 bytes of union storage.
func (a *Address) Flow() DataFlow {
	return *(*DataFlow)(unsafe.Pointer(&a.Data[0]))
}

// SetFlow sets the DataFlow structure into Address.Data.
func (a *Address) SetFlow(f DataFlow) {
	*(*DataFlow)(unsafe.Pointer(&a.Data[0])) = f
}

// Socket returns the DataSocket view of Address.Data.
// Under Windows x64 ABI, DataSocket occupies the full 64 bytes of union storage.
func (a *Address) Socket() DataSocket {
	return *(*DataSocket)(unsafe.Pointer(&a.Data[0]))
}

// SetSocket sets the DataSocket structure into Address.Data.
func (a *Address) SetSocket(s DataSocket) {
	*(*DataSocket)(unsafe.Pointer(&a.Data[0])) = s
}

// Reflect returns the DataReflect view of Address.Data.
// Under Windows x64 ABI, WINDIVERT_DATA_REFLECT occupies the first 32 bytes of union storage;
// the trailing 32 bytes are uninterpreted union padding (Reserved3).
func (a *Address) Reflect() DataReflect {
	return *(*DataReflect)(unsafe.Pointer(&a.Data[0]))
}

// SetReflect sets the DataReflect structure into the first 32 bytes of Address.Data
// and zeroes the trailing 32 bytes of union storage to ensure clean union state.
func (a *Address) SetReflect(r DataReflect) {
	*(*DataReflect)(unsafe.Pointer(&a.Data[0])) = r
	for i := 32; i < 64; i++ {
		a.Data[i] = 0
	}
}

// RawPointer returns an unsafe.Pointer to the address for native invocation.
func (a *Address) RawPointer() unsafe.Pointer {
	return unsafe.Pointer(a)
}
