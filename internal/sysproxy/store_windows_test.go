//go:build windows

package sysproxy

import (
	"bytes"
	"testing"
)

func TestWindowsStoreIsolatedScratchKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry-writing test in short mode")
	}

	// Strictly isolated test subkey under HKCU; never touches real Internet Settings!
	scratchSubkey := `Software\dpibypass_test_scratch`
	store := NewWindowsStore(scratchSubkey)

	// Clean up any pre-existing or post-test key
	defer func() {
		_ = store.DeleteValue("TestDWORD")
		_ = store.DeleteValue("TestString")
		_ = store.DeleteSubkey()
	}()

	// 1. Read non-existent value before key exists: must return Exists: false, nil error
	val, err := store.ReadValue("TestDWORD")
	if err != nil {
		t.Fatalf("unexpected error reading non-existent value: %v", err)
	}
	if val.Exists {
		t.Fatal("expected Exists: false for non-existent value")
	}

	// 2. Write DWORD
	expectedDW := uint32(1080)
	dwBytes := EncodeDWORD(expectedDW)
	if err := store.WriteValue("TestDWORD", REG_DWORD, dwBytes); err != nil {
		t.Fatalf("failed to write DWORD: %v", err)
	}

	// Read back DWORD
	valDW, err := store.ReadValue("TestDWORD")
	if err != nil {
		t.Fatalf("failed to read DWORD: %v", err)
	}
	if !valDW.Exists || valDW.Type != REG_DWORD || !bytes.Equal(valDW.Data, dwBytes) {
		t.Fatalf("DWORD mismatch: exists=%v, type=%d, data=%v", valDW.Exists, valDW.Type, valDW.Data)
	}
	decodedDW, err := DecodeDWORD(valDW.Data)
	if err != nil || decodedDW != expectedDW {
		t.Fatalf("decoded DWORD mismatch: got %d (err: %v), expected %d", decodedDW, err, expectedDW)
	}

	// 3. Write String
	expectedStr := "http=127.0.0.1:1080;https=127.0.0.1:1080"
	strBytes := EncodeString(expectedStr)
	if err := store.WriteValue("TestString", REG_SZ, strBytes); err != nil {
		t.Fatalf("failed to write String: %v", err)
	}

	// Read back String
	valStr, err := store.ReadValue("TestString")
	if err != nil {
		t.Fatalf("failed to read String: %v", err)
	}
	if !valStr.Exists || valStr.Type != REG_SZ || !bytes.Equal(valStr.Data, strBytes) {
		t.Fatalf("String mismatch: exists=%v, type=%d, data=%v", valStr.Exists, valStr.Type, valStr.Data)
	}
	decodedStr, err := DecodeString(valStr.Data)
	if err != nil || decodedStr != expectedStr {
		t.Fatalf("decoded String mismatch: got %q (err: %v), expected %q", decodedStr, err, expectedStr)
	}

	// 4. Delete value
	if err := store.DeleteValue("TestDWORD"); err != nil {
		t.Fatalf("failed to delete value: %v", err)
	}
	valDeleted, err := store.ReadValue("TestDWORD")
	if err != nil {
		t.Fatalf("unexpected error reading deleted value: %v", err)
	}
	if valDeleted.Exists {
		t.Fatal("expected Exists: false after deletion")
	}

	// 5. Test DeleteSubkey
	if err := store.DeleteSubkey(); err != nil {
		t.Fatalf("failed to delete scratch subkey: %v", err)
	}
}
