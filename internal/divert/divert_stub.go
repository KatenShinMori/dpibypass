//go:build !(windows && amd64)

package divert

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

var ErrUnsupportedPlatform = errors.New("WinDivert is only supported on windows/amd64")

type Handle uintptr

const InvalidHandle Handle = ^Handle(0)

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
	ParamQueueTimeDefault   = 2000
	ParamQueueTimeMin       = 100
	ParamQueueTimeMax       = 16000
	ParamQueueSizeDefault   = 4194304
	ParamQueueSizeMin       = 65535
	ParamQueueSizeMax       = 33554432
	BatchMax                = 0xFF
	MTUMax                  = 40 + 0xFFFF

	FilterLoopbackTest = "loopback and outbound and !impostor and ip.DstAddr == 127.0.0.1 and tcp.DstPort == 54321 and tcp.PayloadLength > 0"
	LoopbackTestPort   = 54321

	FilterOutboundProduction = "outbound and !impostor and !loopback and ((ip and tcp and (ip.DstAddr == 195.175.254.2 or ((ip.DstAddr != 1.1.1.1 and ip.DstAddr != 1.0.0.1 and ip.DstAddr != 8.8.8.8 and ip.DstAddr != 8.8.4.4) and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.PayloadLength > 0))) or (ipv6 and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443) and (tcp.Syn or tcp.PayloadLength > 0)) or (udp and udp.DstPort == 443))"
	FilterOutboundWithDNS    = "outbound and !loopback and ((udp and udp.DstPort == 53) or (!impostor and ((ip and tcp and (ip.DstAddr == 195.175.254.2 or tcp.DstPort == 53 or ((ip.DstAddr != 1.1.1.1 and ip.DstAddr != 1.0.0.1 and ip.DstAddr != 8.8.8.8 and ip.DstAddr != 8.8.4.4) and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.PayloadLength > 0))) or (ipv6 and tcp and (((tcp.DstPort == 80 or tcp.DstPort == 443) and (tcp.Syn or tcp.PayloadLength > 0)) or tcp.DstPort == 53)) or (udp and udp.DstPort == 443))))"
	MaxPacketBufferSize      = 65535

	// Structure size and union storage constants (windivert.h v2.2.2).
	AddressSize         = 80
	AddressExpectedSize = AddressSize
	AddressUnionSize    = 64
	DataNetworkSize     = 8
	DataFlowSize        = 64
	DataSocketSize      = 64
	DataReflectSize     = 32
)

type Address struct {
	Timestamp int64
	Bits      uint32
	Reserved2 uint32
	Data      [64]byte
}

type DataNetwork struct {
	IfIdx    uint32
	SubIfIdx uint32
}

type DataFlow struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte
}

type DataSocket struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte
}

type DataReflect struct {
	Timestamp int64
	ProcessID uint32
	Layer     uint32
	Flags     uint64
	Priority  int16
	_         [6]byte
}

func (a *Address) Layer() uint8     { return uint8(a.Bits & 0xFF) }
func (a *Address) SetLayer(l uint8) { a.Bits = (a.Bits &^ 0xFF) | uint32(l) }
func (a *Address) Event() uint8     { return uint8((a.Bits >> 8) & 0xFF) }
func (a *Address) SetEvent(e uint8) { a.Bits = (a.Bits &^ (0xFF << 8)) | (uint32(e) << 8) }
func (a *Address) Sniffed() bool    { return (a.Bits & (1 << 16)) != 0 }
func (a *Address) SetSniffed(v bool) {
	if v {
		a.Bits |= (1 << 16)
	} else {
		a.Bits &^= (1 << 16)
	}
}
func (a *Address) Outbound() bool { return (a.Bits & (1 << 17)) != 0 }
func (a *Address) SetOutbound(v bool) {
	if v {
		a.Bits |= (1 << 17)
	} else {
		a.Bits &^= (1 << 17)
	}
}
func (a *Address) Loopback() bool { return (a.Bits & (1 << 18)) != 0 }
func (a *Address) SetLoopback(v bool) {
	if v {
		a.Bits |= (1 << 18)
	} else {
		a.Bits &^= (1 << 18)
	}
}
func (a *Address) Impostor() bool { return (a.Bits & (1 << 19)) != 0 }
func (a *Address) SetImpostor(v bool) {
	if v {
		a.Bits |= (1 << 19)
	} else {
		a.Bits &^= (1 << 19)
	}
}
func (a *Address) IPv6() bool { return (a.Bits & (1 << 20)) != 0 }
func (a *Address) SetIPv6(v bool) {
	if v {
		a.Bits |= (1 << 20)
	} else {
		a.Bits &^= (1 << 20)
	}
}
func (a *Address) IPChecksum() bool { return (a.Bits & (1 << 21)) != 0 }
func (a *Address) SetIPChecksum(v bool) {
	if v {
		a.Bits |= (1 << 21)
	} else {
		a.Bits &^= (1 << 21)
	}
}
func (a *Address) TCPChecksum() bool { return (a.Bits & (1 << 22)) != 0 }
func (a *Address) SetTCPChecksum(v bool) {
	if v {
		a.Bits |= (1 << 22)
	} else {
		a.Bits &^= (1 << 22)
	}
}
func (a *Address) UDPChecksum() bool { return (a.Bits & (1 << 23)) != 0 }
func (a *Address) SetUDPChecksum(v bool) {
	if v {
		a.Bits |= (1 << 23)
	} else {
		a.Bits &^= (1 << 23)
	}
}
func (a *Address) Reserved1() uint8     { return uint8((a.Bits >> 24) & 0xFF) }
func (a *Address) SetReserved1(r uint8) { a.Bits = (a.Bits &^ (0xFF << 24)) | (uint32(r) << 24) }

func (a *Address) Network() DataNetwork {
	return DataNetwork{
		IfIdx:    binary.LittleEndian.Uint32(a.Data[0:4]),
		SubIfIdx: binary.LittleEndian.Uint32(a.Data[4:8]),
	}
}

func (a *Address) SetNetwork(n DataNetwork) {
	binary.LittleEndian.PutUint32(a.Data[0:4], n.IfIdx)
	binary.LittleEndian.PutUint32(a.Data[4:8], n.SubIfIdx)
	for i := 8; i < 64; i++ {
		a.Data[i] = 0
	}
}

func (a *Address) Flow() DataFlow {
	return *(*DataFlow)(unsafe.Pointer(&a.Data[0]))
}

func (a *Address) SetFlow(f DataFlow) {
	*(*DataFlow)(unsafe.Pointer(&a.Data[0])) = f
}

func (a *Address) Socket() DataSocket {
	return *(*DataSocket)(unsafe.Pointer(&a.Data[0]))
}

func (a *Address) SetSocket(s DataSocket) {
	*(*DataSocket)(unsafe.Pointer(&a.Data[0])) = s
}

func (a *Address) Reflect() DataReflect {
	return *(*DataReflect)(unsafe.Pointer(&a.Data[0]))
}

func (a *Address) SetReflect(r DataReflect) {
	*(*DataReflect)(unsafe.Pointer(&a.Data[0])) = r
	for i := 32; i < 64; i++ {
		a.Data[i] = 0
	}
}

func (a *Address) RawPointer() unsafe.Pointer {
	return unsafe.Pointer(a)
}

func IsDLLLoaded() bool {
	return false
}

func Open(filter string, layer uint32, priority int16, flags uint64) (Handle, error) {
	return InvalidHandle, ErrUnsupportedPlatform
}

func Recv(h Handle, packet []byte, addr *Address) (int, error) {
	return 0, ErrUnsupportedPlatform
}

func Send(h Handle, packet []byte, addr *Address) (int, error) {
	return 0, ErrUnsupportedPlatform
}

func Close(h Handle) error {
	return ErrUnsupportedPlatform
}

func SetParam(h Handle, param uint32, value uint64) error {
	return ErrUnsupportedPlatform
}

func IsAvailable() bool {
	return false
}

func IsElevated() (bool, error) {
	return false, ErrUnsupportedPlatform
}
