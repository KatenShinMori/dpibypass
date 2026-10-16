package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"dpibypass/internal/divert"
)

func TestRunSelfTest_Direct(t *testing.T) {
	if divert.IsDLLLoaded() {
		t.Fatal("Precondition failed: WinDivert.dll is loaded before self-test")
	}

	exitCode := runSelfTest()
	if exitCode != 0 {
		t.Fatalf("runSelfTest() returned non-zero exit code: %d", exitCode)
	}

	if divert.IsDLLLoaded() {
		t.Fatal("Postcondition failed: WinDivert.dll was loaded by runSelfTest()")
	}
}

func TestMain_CLIModes(t *testing.T) {
	// Build or locate test binary, or test main via helper process
	// Testing printHelp output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w

	printHelp()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "packetlab - Phase 2.1A") {
		t.Fatalf("printHelp output missing expected header: %s", output)
	}
	if !strings.Contains(output, "--self-test") {
		t.Fatalf("printHelp output missing --self-test documentation")
	}
}

func findMainPath() (string, string) {
	if _, err := os.Stat("main.go"); err == nil {
		return "main.go", "."
	}
	p := filepath.Join("cmd", "packetlab", "main.go")
	if _, err := os.Stat(p); err == nil {
		return p, filepath.Join(".", "cmd", "packetlab")
	}
	return "main.go", "."
}

func TestCLI_SubprocessInvariants(t *testing.T) {
	// Build temporary packetlab binary
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "packetlab_test.exe")

	_, pkgDir := findMainPath()
	cmd := exec.Command("go", "build", "-o", binPath, pkgDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v, output: %s", err, string(out))
	}

	tests := []struct {
		name         string
		args         []string
		wantExitCode int
		wantOutput   string
	}{
		{
			name:         "No arguments prints help and exits 0",
			args:         nil,
			wantExitCode: 0,
			wantOutput:   "USAGE:",
		},
		{
			name:         "Help flag exits 0",
			args:         []string{"--help"},
			wantExitCode: 0,
			wantOutput:   "USAGE:",
		},
		{
			name:         "Short help flag -h exits 0",
			args:         []string{"-h"},
			wantExitCode: 0,
			wantOutput:   "USAGE:",
		},
		{
			name:         "Positional help argument exits 0",
			args:         []string{"help"},
			wantExitCode: 0,
			wantOutput:   "USAGE:",
		},
		{
			name:         "Self-test flag exits 0 and verifies pure-Go offline mode",
			args:         []string{"--self-test"},
			wantExitCode: 0,
			wantOutput:   "ALL 6 OF 6 OFFLINE CHECKS PASSED",
		},
		{
			name:         "Single hyphen self-test flag exits 0",
			args:         []string{"-self-test"},
			wantExitCode: 0,
			wantOutput:   "ALL 6 OF 6 OFFLINE CHECKS PASSED",
		},
		{
			name:         "Unrecognized flag exits 1",
			args:         []string{"--invalid-flag"},
			wantExitCode: 1,
			wantOutput:   "unrecognized argument",
		},
		{
			name:         "Extra trailing arguments exit 1",
			args:         []string{"--self-test", "extra-arg"},
			wantExitCode: 1,
			wantOutput:   "unexpected extra arguments",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subCmd := exec.Command(binPath, tc.args...)
			out, err := subCmd.CombinedOutput()
			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("Unexpected execution error: %v", err)
				}
			}

			if exitCode != tc.wantExitCode {
				t.Fatalf("Exit code = %d, want %d (output: %s)", exitCode, tc.wantExitCode, string(out))
			}
			if !strings.Contains(string(out), tc.wantOutput) {
				t.Fatalf("Output missing %q; got: %s", tc.wantOutput, string(out))
			}
		})
	}
}

func TestCLI_StructuralIsolation(t *testing.T) {
	// Statically inspect cmd/packetlab/main.go AST to structurally enforce:
	// 1. Zero network package imports (no "net", "net/http", etc.)
	// 2. Zero low-level OS/syscall imports (no "syscall", "golang.org/x/sys/windows", "unsafe")
	// 3. From "dpibypass/internal/divert", ONLY divert.IsDLLLoaded is permitted.
	//    divert.Open, divert.Recv, divert.Send, divert.Close are structurally forbidden.
	mainFile, _ := findMainPath()
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, mainFile, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("Failed to parse %s: %v", mainFile, err)
	}

	allowedImports := map[string]bool{
		`"bytes"`:                        true,
		`"crypto/sha256"`:                true,
		`"encoding/hex"`:                 true,
		`"fmt"`:                          true,
		`"os"`:                           true,
		`"dpibypass/internal/divert"`:    true,
		`"dpibypass/internal/packetlab"`: true,
	}

	for _, imp := range node.Imports {
		pathVal := imp.Path.Value
		if !allowedImports[pathVal] {
			t.Fatalf("Structural isolation violation: main.go imports unapproved package %s", pathVal)
		}
	}

	// Full AST inspection of main.go to ensure divert.Open, divert.Recv, divert.Send, divert.Close
	// are never called or referenced.
	fullNode, err := parser.ParseFile(fset, mainFile, nil, 0)
	if err != nil {
		t.Fatalf("Failed to parse full %s: %v", mainFile, err)
	}

	forbiddenDivertSymbols := map[string]bool{
		"Open":          true,
		"Recv":          true,
		"Send":          true,
		"Close":         true,
		"Handle":        true,
		"InvalidHandle": true,
	}

	ast.Inspect(fullNode, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "divert" {
			if forbiddenDivertSymbols[sel.Sel.Name] {
				t.Fatalf("Structural isolation violation: main.go references forbidden divert symbol 'divert.%s'", sel.Sel.Name)
			}
			if sel.Sel.Name != "IsDLLLoaded" {
				t.Fatalf("Structural isolation violation: main.go references unapproved divert symbol 'divert.%s'", sel.Sel.Name)
			}
		}
		return true
	})
}
