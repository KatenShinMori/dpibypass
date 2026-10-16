package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"dpibypass/internal/divert"
	"dpibypass/internal/packetlab"
)

const usageText = `packetlab - Phase 2.1A Standalone Offline Packet Laboratory

USAGE:
    packetlab --help
        Display this help documentation.

    packetlab --self-test
        Execute pure-Go offline packet parsing, deterministic segmentation,
        checksum recalculation, and sequence continuity verification.

DESCRIPTION:
    packetlab is an experimental testbed for evaluating packet-level IPv4/TCP
    transformations in userspace without driver elevation or network interception.

    This build (Phase 2.1A) is strictly offline and fail-closed:
      * No kernel drivers (WinDivert64.sys) are downloaded or loaded.
      * No dynamic library procedures (WinDivert.dll) are invoked.
      * No network interfaces, sockets, or live packets are captured or transmitted.
      * All tests run against synthetic in-memory fixtures only.
`

func printHelp() {
	fmt.Print(usageText)
}

func runSelfTest() int {
	fmt.Println("[packetlab] ================================================================")
	fmt.Println("[packetlab] Phase 2.1A Pure-Go Offline Self-Test")
	fmt.Println("[packetlab] ================================================================")
	fmt.Println("[packetlab] NOTICE: Operating strictly in pure-Go offline simulation mode.")
	fmt.Println("[packetlab] NOTICE: No kernel driver loaded, no DLL resolved, no packets transmitted.")
	fmt.Println()

	// 1. Synthetic packet creation
	cfg := packetlab.DefaultPacketConfig()
	cfg.Payload = []byte("GET /updates HTTP/1.1\r\nHost: updates.discord.com\r\nUser-Agent: packetlab-test/1.0\r\nAccept: */*\r\n\r\n")
	origPayloadLen := len(cfg.Payload)

	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		fmt.Printf("[packetlab] FAIL: Failed to construct synthetic packet: %v\n", err)
		return 1
	}

	origValidIP, err := packetlab.VerifyIPv4Checksum(pkt)
	if err != nil || !origValidIP {
		fmt.Printf("[packetlab] FAIL: Synthetic packet IPv4 checksum invalid: %v\n", err)
		return 1
	}
	origValidTCP, err := packetlab.VerifyTCPChecksum(pkt)
	if err != nil || !origValidTCP {
		fmt.Printf("[packetlab] FAIL: Synthetic packet TCP checksum invalid: %v\n", err)
		return 1
	}
	fmt.Printf("[packetlab] [1/6] Synthetic IPv4/TCP packet generated (%d bytes, payload %d bytes): PASS\n", len(pkt), origPayloadLen)

	// 2. Odd-offset segmentation test
	splitOffset := 35 // odd offset
	first, second, err := packetlab.SplitIPv4TCPPacket(pkt, splitOffset)
	if err != nil {
		fmt.Printf("[packetlab] FAIL: SplitIPv4TCPPacket failed at offset %d: %v\n", splitOffset, err)
		return 1
	}

	p1, err := packetlab.ParseIPv4TCPPacket(first)
	if err != nil {
		fmt.Printf("[packetlab] FAIL: Parsing first segment failed: %v\n", err)
		return 1
	}
	p2, err := packetlab.ParseIPv4TCPPacket(second)
	if err != nil {
		fmt.Printf("[packetlab] FAIL: Parsing second segment failed: %v\n", err)
		return 1
	}

	if len(p1.Payload) != splitOffset || len(p2.Payload) != (origPayloadLen-splitOffset) {
		fmt.Printf("[packetlab] FAIL: Payload slice lengths invalid: seg1=%d, seg2=%d\n", len(p1.Payload), len(p2.Payload))
		return 1
	}
	fmt.Printf("[packetlab] [2/6] Odd-length split (offset=%d, seg1=%dB, seg2=%dB): PASS\n", splitOffset, len(p1.Payload), len(p2.Payload))

	// 3. Sequence number continuity and flag semantics
	expectedSeq2 := cfg.SeqNum + uint32(splitOffset)
	if p1.SeqNum != cfg.SeqNum || p2.SeqNum != expectedSeq2 {
		fmt.Printf("[packetlab] FAIL: Sequence continuity broken: seg1=%d, seg2=%d (want %d)\n", p1.SeqNum, p2.SeqNum, expectedSeq2)
		return 1
	}
	if (p1.TCPFlags & packetlab.TCPFlagPSH) != 0 {
		fmt.Printf("[packetlab] FAIL: Segment 1 must not carry PSH flag (got 0x%02x)\n", p1.TCPFlags)
		return 1
	}
	if (p2.TCPFlags & packetlab.TCPFlagPSH) == 0 {
		fmt.Printf("[packetlab] FAIL: Segment 2 must preserve PSH flag (got 0x%02x)\n", p2.TCPFlags)
		return 1
	}
	fmt.Printf("[packetlab] [3/6] TCP sequence continuity (%d -> %d) & PSH flag distribution: PASS\n", p1.SeqNum, p2.SeqNum)

	// 4. Bit-for-bit payload reconstruction & SHA-256 hash validation
	reconstructed := append(append([]byte(nil), p1.Payload...), p2.Payload...)
	if !bytes.Equal(reconstructed, cfg.Payload) {
		fmt.Println("[packetlab] FAIL: Reconstructed payload does not match original bytes!")
		return 1
	}
	hOrig := sha256.Sum256(cfg.Payload)
	hRecon := sha256.Sum256(reconstructed)
	if hOrig != hRecon {
		fmt.Printf("[packetlab] FAIL: SHA-256 mismatch: %s != %s\n", hex.EncodeToString(hOrig[:]), hex.EncodeToString(hRecon[:]))
		return 1
	}
	fmt.Printf("[packetlab] [4/6] Payload bit-preservation (SHA-256 %s...): PASS\n", hex.EncodeToString(hOrig[:8]))

	// 5. Output checksum verification (IPv4 header and TCP pseudo-header)
	vIP1, errIP1 := packetlab.VerifyIPv4Checksum(first)
	vTCP1, errTCP1 := packetlab.VerifyTCPChecksum(first)
	vIP2, errIP2 := packetlab.VerifyIPv4Checksum(second)
	vTCP2, errTCP2 := packetlab.VerifyTCPChecksum(second)
	if !vIP1 || !vTCP1 || !vIP2 || !vTCP2 || errIP1 != nil || errTCP1 != nil || errIP2 != nil || errTCP2 != nil {
		fmt.Printf("[packetlab] FAIL: Checksum verification failure: seg1(IP=%v, err=%v, TCP=%v, err=%v), seg2(IP=%v, err=%v, TCP=%v, err=%v)\n",
			vIP1, errIP1, vTCP1, errTCP1, vIP2, errIP2, vTCP2, errTCP2)
		return 1
	}
	fmt.Printf("[packetlab] [5/6] Segment RFC 791/793 checksum validation (IP1=%v, TCP1=%v, IP2=%v, TCP2=%v): PASS\n", vIP1, vTCP1, vIP2, vTCP2)

	// 6. Security invariant: verify WinDivert.dll was not loaded
	if divert.IsDLLLoaded() {
		fmt.Println("[packetlab] CRITICAL SAFETY VIOLATION: WinDivert.dll is loaded in process memory!")
		return 1
	}
	fmt.Println("[packetlab] [6/6] Zero-driver / zero-DLL execution invariant verified: PASS")

	fmt.Println()
	fmt.Println("[packetlab] ================================================================")
	fmt.Println("[packetlab] ALL 6 OF 6 OFFLINE CHECKS PASSED.")
	fmt.Println("[packetlab] Pure-Go IPv4/TCP segmentation engine validated successfully.")
	fmt.Println("[packetlab] ================================================================")
	return 0
}

func main() {
	if len(os.Args) <= 1 {
		printHelp()
		os.Exit(0)
	}

	if len(os.Args) > 2 {
		fmt.Fprintf(os.Stderr, "packetlab: unexpected extra arguments: %v\n\n", os.Args[2:])
		printHelp()
		os.Exit(1)
	}

	arg := os.Args[1]
	switch arg {
	case "--help", "-help", "-h", "help":
		printHelp()
		os.Exit(0)
	case "--self-test", "-self-test":
		exitCode := runSelfTest()
		os.Exit(exitCode)
	default:
		fmt.Fprintf(os.Stderr, "packetlab: unrecognized argument '%s'\n\n", arg)
		printHelp()
		os.Exit(1)
	}
}
