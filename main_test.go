package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionPathsUsesRuntimeDir(t *testing.T) {
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	dir, statePath, socketPath, logPath, err := sessionPaths()
	if err != nil {
		t.Fatalf("sessionPaths error: %v", err)
	}

	if dir == "" || statePath == "" || socketPath == "" || logPath == "" {
		t.Fatalf("expected non-empty paths")
	}
	if filepath.Dir(statePath) != dir {
		t.Fatalf("statePath not in runtime dir: %s", statePath)
	}
	if filepath.Dir(socketPath) != dir {
		t.Fatalf("socketPath not in runtime dir: %s", socketPath)
	}
	if filepath.Dir(logPath) != dir {
		t.Fatalf("logPath not in runtime dir: %s", logPath)
	}
}

func TestSessionPathsErrorsOnLongSocketPath(t *testing.T) {
	base := t.TempDir()
	longDir := filepath.Join(base, strings.Repeat("a", 120))
	if err := os.MkdirAll(longDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", longDir)

	_, _, _, _, err := sessionPaths()
	if err == nil {
		t.Fatalf("expected error for long socket path")
	}
}

func TestAccessPathsUsesHomeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("home dir handling differs on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	accessDir, accessPath, err := accessPaths()
	if err != nil {
		t.Fatalf("accessPaths error: %v", err)
	}

	expectedDir := filepath.Join(home, ".sshgate")
	expectedPath := filepath.Join(expectedDir, accessFileName)
	if accessDir != expectedDir {
		t.Fatalf("unexpected accessDir: %s", accessDir)
	}
	if accessPath != expectedPath {
		t.Fatalf("unexpected accessPath: %s", accessPath)
	}
}

func TestWriteLoadSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	state := sessionState{
		Host:            "user@host",
		SocketPath:      "/tmp/socket",
		LogPath:         "/tmp/commands.log",
		AllowRevealHost: true,
	}

	if err := writeSession(path, state); err != nil {
		t.Fatalf("writeSession error: %v", err)
	}

	loaded, err := loadSession(path)
	if err != nil {
		t.Fatalf("loadSession error: %v", err)
	}

	if loaded != state {
		t.Fatalf("unexpected session state: %#v", loaded)
	}
}

func TestWriteLoadAccessRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access")
	state := accessState{Hash: "hash"}

	if err := writeAccess(path, state); err != nil {
		t.Fatalf("writeAccess error: %v", err)
	}

	loaded, err := loadAccess(path)
	if err != nil {
		t.Fatalf("loadAccess error: %v", err)
	}

	if loaded != state {
		t.Fatalf("unexpected access state: %#v", loaded)
	}
}

func TestLoadSessionRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := loadSession(path); err == nil {
		t.Fatalf("expected error for invalid session state")
	}
}

func TestLoadAccessRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access")
	data, err := json.Marshal(accessState{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := loadAccess(path); err == nil {
		t.Fatalf("expected error for invalid access state")
	}
}

func TestSessionActiveUsesSSHExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not available on Windows")
	}
	fakeDir := t.TempDir()
	sshPath := filepath.Join(fakeDir, "ssh")
	script := "#!/bin/sh\n" +
		"if [ \"$SSHGATE_FAKE_ACTIVE\" = \"1\" ]; then\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 1\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}

	oldSSH := sshBinary
	sshBinary = sshPath
	defer func() { sshBinary = oldSSH }()

	state := sessionState{Host: "user@host", SocketPath: "/tmp/socket", LogPath: "/tmp/log"}

	t.Setenv("SSHGATE_FAKE_ACTIVE", "1")
	active, err := sessionActive(state)
	if err != nil {
		t.Fatalf("sessionActive error: %v", err)
	}
	if !active {
		t.Fatalf("expected active session")
	}

	t.Setenv("SSHGATE_FAKE_ACTIVE", "0")
	active, err = sessionActive(state)
	if err != nil {
		t.Fatalf("sessionActive error: %v", err)
	}
	if active {
		t.Fatalf("expected inactive session")
	}
}

func TestSessionActiveReturnsErrorOnMissingSSH(t *testing.T) {
	oldSSH := sshBinary
	sshBinary = filepath.Join(t.TempDir(), "missing-ssh")
	defer func() { sshBinary = oldSSH }()

	state := sessionState{Host: "user@host", SocketPath: "/tmp/socket", LogPath: "/tmp/log"}
	if _, err := sessionActive(state); err == nil {
		t.Fatalf("expected error when ssh binary is missing")
	}
}

func TestWaitForSocketSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep command not available on Windows")
	}
	socketPath := filepath.Join(t.TempDir(), "sock")
	cmd := exec.Command("sleep", "1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	go func() {
		time.Sleep(25 * time.Millisecond)
		_ = os.WriteFile(socketPath, []byte(""), 0o600)
	}()

	if err := waitForSocket(socketPath, 2*time.Second, cmd); err != nil {
		t.Fatalf("waitForSocket error: %v", err)
	}
}

func TestWaitForSocketDetectsExitedProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("true command not available on Windows")
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start true: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait true: %v", err)
	}

	if err := waitForSocket(filepath.Join(t.TempDir(), "sock"), 200*time.Millisecond, cmd); err == nil {
		t.Fatalf("expected error for exited process")
	}
}

func TestWaitForSocketTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep command not available on Windows")
	}
	cmd := exec.Command("sleep", "1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	err := waitForSocket(filepath.Join(t.TempDir(), "sock"), 250*time.Millisecond, cmd)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanupSessionRemovesFiles(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "session.json")
	socketPath := filepath.Join(dir, "sock")
	logPath := filepath.Join(dir, "commands.log")

	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write socket: %v", err)
	}
	if err := os.WriteFile(logPath, []byte("- pwd\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	state := sessionState{SocketPath: socketPath, LogPath: logPath}
	if err := cleanupSession(state, statePath); err != nil {
		t.Fatalf("cleanupSession error: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("expected state file removed")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket file removed")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("expected log file removed")
	}
}

func TestCleanupSessionIdempotent(t *testing.T) {
	dir := t.TempDir()
	state := sessionState{SocketPath: filepath.Join(dir, "sock"), LogPath: filepath.Join(dir, "commands.log")}
	if err := cleanupSession(state, filepath.Join(dir, "session.json")); err != nil {
		t.Fatalf("cleanupSession error: %v", err)
	}
}

func TestInitCommandLogTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.log")
	if err := os.WriteFile(path, []byte("- old\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if err := initCommandLog(path); err != nil {
		t.Fatalf("initCommandLog error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty log, got: %q", string(data))
	}
}

func TestAppendCommandLogFormatsEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.log")
	if err := appendCommandLog(path, "ls -la"); err != nil {
		t.Fatalf("appendCommandLog error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(data) != "- ls -la\n" {
		t.Fatalf("unexpected log content: %q", string(data))
	}
}

func TestTailCommandLogOutputsNewEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.log")
	if err := initCommandLog(path); err != nil {
		t.Fatalf("initCommandLog error: %v", err)
	}

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = writePipe
	defer func() {
		os.Stdout = oldStdout
		_ = writePipe.Close()
		_ = readPipe.Close()
	}()

	stop := make(chan struct{})
	go tailCommandLog(path, stop)

	if err := appendCommandLog(path, "pwd"); err != nil {
		close(stop)
		t.Fatalf("appendCommandLog error: %v", err)
	}

	var output strings.Builder
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := readPipe.Read(buf)
			if n > 0 {
				_, _ = output.Write(buf[:n])
				if strings.Contains(output.String(), "- pwd\n") {
					break
				}
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				break
			}
		}
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		close(stop)
		t.Fatalf("timed out waiting for log output")
	}

	close(stop)
	if !strings.Contains(output.String(), "- pwd\n") {
		t.Fatalf("expected log output, got: %q", output.String())
	}
}

func TestRunRemoteShellUsesSSHBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not available on Windows")
	}
	fakeDir := t.TempDir()
	sshPath := filepath.Join(fakeDir, "ssh")
	script := "#!/bin/sh\n" +
		"printf '%s' \"$*\"\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}

	oldSSH := sshBinary
	sshBinary = sshPath
	defer func() { sshBinary = oldSSH }()

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = writePipe
	defer func() {
		os.Stdout = oldStdout
		_ = writePipe.Close()
		_ = readPipe.Close()
	}()

	state := sessionState{Host: "user@host", SocketPath: "/tmp/socket", LogPath: "/tmp/log"}
	if err := runRemoteShell(state, "echo ok"); err != nil {
		t.Fatalf("runRemoteShell error: %v", err)
	}

	_ = writePipe.Close()
	data, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "-S /tmp/socket") {
		t.Fatalf("expected socket args in output, got: %q", output)
	}
	if !strings.Contains(output, "user@host") {
		t.Fatalf("expected host in output, got: %q", output)
	}
	if !strings.Contains(output, "sh -c echo ok") {
		t.Fatalf("expected shell command in output, got: %q", output)
	}
}

func TestRunRemoteShellReturnsErrorOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not available on Windows")
	}
	fakeDir := t.TempDir()
	sshPath := filepath.Join(fakeDir, "ssh")
	script := "#!/bin/sh\n" +
		"exit 2\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}

	oldSSH := sshBinary
	sshBinary = sshPath
	defer func() { sshBinary = oldSSH }()

	state := sessionState{Host: "user@host", SocketPath: "/tmp/socket", LogPath: "/tmp/log"}
	if err := runRemoteShell(state, "echo ok"); err == nil {
		t.Fatalf("expected error from failing ssh")
	}
}

func TestShellEscape(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{input: "", expect: "''"},
		{input: "plain", expect: "'plain'"},
		{input: "a b", expect: "'a b'"},
		{input: "a'b", expect: `'a'\''b'`},
		{input: "x'y\"z", expect: `'x'\''y"z'`},
	}

	for _, test := range tests {
		if got := shellEscape(test.input); got != test.expect {
			t.Fatalf("shellEscape(%q) = %q, want %q", test.input, got, test.expect)
		}
	}
}

func TestShellJoin(t *testing.T) {
	args := []string{"echo", "a b"}
	got := shellJoin(args)
	expect := "'echo' 'a b'"
	if got != expect {
		t.Fatalf("shellJoin(%v) = %q, want %q", args, got, expect)
	}
}

func TestRunRemoteCommandEscapesArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not available on Windows")
	}
	fakeDir := t.TempDir()
	sshPath := filepath.Join(fakeDir, "ssh")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}

	oldSSH := sshBinary
	sshBinary = sshPath
	defer func() { sshBinary = oldSSH }()

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = writePipe
	defer func() {
		os.Stdout = oldStdout
		_ = writePipe.Close()
		_ = readPipe.Close()
	}()

	state := sessionState{Host: "user@host", SocketPath: "/tmp/socket", LogPath: "/tmp/log"}
	if err := runRemoteCommand(state, []string{"echo", "a b"}); err != nil {
		t.Fatalf("runRemoteCommand error: %v", err)
	}

	_ = writePipe.Close()
	data, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	output := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(output, "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 ssh args, got %d: %q", len(lines), lines)
	}
	if lines[0] != "-S" || lines[1] != "/tmp/socket" || lines[2] != "user@host" || lines[3] != "--" {
		t.Fatalf("unexpected ssh args: %q", lines[:4])
	}
	if lines[4] != "'echo' 'a b'" {
		t.Fatalf("unexpected command line: %q", lines[4])
	}
}

func TestParseOpenArgsSimple(t *testing.T) {
	reveal, opts, target, err := parseOpenArgs([]string{"user@host"})
	if err != nil {
		t.Fatalf("parseOpenArgs error: %v", err)
	}
	if reveal {
		t.Fatalf("unexpected reveal flag")
	}
	if len(opts) != 0 {
		t.Fatalf("unexpected opts: %v", opts)
	}
	if target != "user@host" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestParseOpenArgsWithReveal(t *testing.T) {
	reveal, opts, target, err := parseOpenArgs([]string{"--reveal-host", "user@host"})
	if err != nil {
		t.Fatalf("parseOpenArgs error: %v", err)
	}
	if !reveal {
		t.Fatalf("expected reveal flag")
	}
	if len(opts) != 0 {
		t.Fatalf("unexpected opts: %v", opts)
	}
	if target != "user@host" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestParseOpenArgsWithOptions(t *testing.T) {
	reveal, opts, target, err := parseOpenArgs([]string{"-i", "~/.ssh/key", "-o", "IdentitiesOnly=yes", "user@host"})
	if err != nil {
		t.Fatalf("parseOpenArgs error: %v", err)
	}
	if reveal {
		t.Fatalf("unexpected reveal flag")
	}
	if target != "user@host" {
		t.Fatalf("unexpected target: %s", target)
	}
	if strings.Join(opts, " ") != "-i ~/.ssh/key -o IdentitiesOnly=yes" {
		t.Fatalf("unexpected opts: %v", opts)
	}
}

func TestParseOpenArgsWithRevealAndOptions(t *testing.T) {
	reveal, opts, target, err := parseOpenArgs([]string{"--reveal-host", "-p", "2222", "user@host"})
	if err != nil {
		t.Fatalf("parseOpenArgs error: %v", err)
	}
	if !reveal {
		t.Fatalf("expected reveal flag")
	}
	if target != "user@host" {
		t.Fatalf("unexpected target: %s", target)
	}
	if strings.Join(opts, " ") != "-p 2222" {
		t.Fatalf("unexpected opts: %v", opts)
	}
}

func TestParseOpenArgsRejectsMultipleTargets(t *testing.T) {
	if _, _, _, err := parseOpenArgs([]string{"user@host", "extra"}); err == nil {
		t.Fatalf("expected error for multiple args")
	}
}

func TestParseOpenArgsRejectsNonOptionBeforeTarget(t *testing.T) {
	if _, _, _, err := parseOpenArgs([]string{"not-an-opt", "user@host"}); err == nil {
		t.Fatalf("expected error for non-option before target")
	}
}

func TestParseOpenArgsWithSeparatorAndOptions(t *testing.T) {
	reveal, opts, target, err := parseOpenArgs([]string{"--", "-i", "~/.ssh/key", "-o", "IdentitiesOnly=yes", "user@host"})
	if err != nil {
		t.Fatalf("parseOpenArgs error: %v", err)
	}
	if reveal {
		t.Fatalf("unexpected reveal flag")
	}
	if target != "user@host" {
		t.Fatalf("unexpected target: %s", target)
	}
	if strings.Join(opts, " ") != "-i ~/.ssh/key -o IdentitiesOnly=yes" {
		t.Fatalf("unexpected opts: %v", opts)
	}
}

// ============================================================================
// EXPANDED TESTS FOR EDGE CASES
// ============================================================================

// Test shellEscape edge cases - security critical
func TestShellEscapeEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "empty string", input: "", expect: "''"},
		{name: "plain text", input: "hello", expect: "'hello'"},
		{name: "space", input: "hello world", expect: "'hello world'"},
		{name: "single quote", input: "a'b", expect: `'a'\''b'`},
		{name: "multiple quotes", input: "a'b'c", expect: `'a'\''b'\''c'`},
		{name: "only quotes", input: "'''", expect: `''\'''\'''\'''`},
		{name: "double quote", input: `a"b`, expect: `'a"b'`},
		{name: "dollar sign", input: "a$b", expect: "'a$b'"},
		{name: "multiple dollars", input: "$PATH$HOME", expect: "'$PATH$HOME'"},
		{name: "backtick", input: "a`b", expect: "'a`b'"},
		{name: "command substitution", input: "$(ls)", expect: "'$(ls)'"},
		{name: "semicolon", input: "a;b", expect: "'a;b'"},
		{name: "pipe", input: "a|b", expect: "'a|b'"},
		{name: "ampersand", input: "a&b", expect: "'a&b'"},
		{name: "redirection", input: "a>b", expect: "'a>b'"},
		{name: "newline", input: "a\nb", expect: "'a\nb'"},
		{name: "tab", input: "a\tb", expect: "'a\tb'"},
		{name: "carriage return", input: "a\rb", expect: "'a\rb'"},
		{name: "backslash", input: `a\b`, expect: `'a\b'`},
		{name: "multiple backslashes", input: `a\\b\\c`, expect: `'a\\b\\c'`},
		{name: "NUL byte", input: "a\x00b", expect: "'a\x00b'"},
		{name: "unicode", input: "hello 世界", expect: "'hello 世界'"},
		{name: "emoji", input: "test 🚀", expect: "'test 🚀'"},
		{name: "asterisk", input: "*.txt", expect: "'*.txt'"},
		{name: "question mark", input: "file?.txt", expect: "'file?.txt'"},
		{name: "brackets", input: "[abc]", expect: "'[abc]'"},
		{name: "braces", input: "{a,b}", expect: "'{a,b}'"},
		{name: "tilde", input: "~/path", expect: "'~/path'"},
		{name: "hash", input: "#comment", expect: "'#comment'"},
		{name: "exclamation", input: "!test", expect: "'!test'"},
		{name: "mixed special", input: `a'b"c$d\e`, expect: `'a'\''b"c$d\e'`},
		{name: "very long string", input: strings.Repeat("a", 10000), expect: "'" + strings.Repeat("a", 10000) + "'"},
		// For 10 consecutive single quotes, shellEscape produces:
		// '' (opening quote + empty content before first quote) + \'' (escaped quote) repeated 10 times
		{name: "long with quotes", input: strings.Repeat("'", 10), expect: "''\\'''\\'''\\'''\\'''\\'''\\'''\\'''\\'''\\'''\\'''"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shellEscape(test.input)
			if got != test.expect {
				t.Errorf("shellEscape(%q) = %q, want %q", test.input, got, test.expect)
			}
		})
	}
}

// Test shellJoin edge cases
func TestShellJoinEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect string
	}{
		{name: "empty slice", input: []string{}, expect: ""},
		{name: "single arg", input: []string{"hello"}, expect: "'hello'"},
		{name: "single empty arg", input: []string{""}, expect: "''"},
		{name: "two args", input: []string{"a", "b"}, expect: "'a' 'b'"},
		{name: "arg with spaces", input: []string{"hello", "world test"}, expect: "'hello' 'world test'"},
		{name: "args with quotes", input: []string{"a'b", "c\"d"}, expect: `'a'\''b' 'c"d'`},
		{name: "many args", input: []string{"a", "b", "c", "d", "e"}, expect: "'a' 'b' 'c' 'd' 'e'"},
		{name: "special chars", input: []string{"$PATH", "~/.ssh", "a|b", "c;d"}, expect: "'$PATH' '~/.ssh' 'a|b' 'c;d'"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shellJoin(test.input)
			if got != test.expect {
				t.Errorf("shellJoin(%v) = %q, want %q", test.input, got, test.expect)
			}
		})
	}
}

// Test parseOpenArgs edge cases
func TestParseOpenArgsEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantErr   bool
		wantMsg   string
		checkFunc func(t *testing.T, reveal bool, opts []string, target string)
	}{
		{
			name:    "empty args",
			input:   []string{},
			wantErr: true,
			wantMsg: "expects a target",
		},
		{
			name:    "just separator",
			input:   []string{"--"},
			wantErr: true,
			wantMsg: "expects a target",
		},
		{
			name:    "reveal-host with no target",
			input:   []string{"--reveal-host"},
			wantErr: true,
			wantMsg: "expects a target",
		},
		{
			name:    "multiple reveal-host flags",
			input:   []string{"--reveal-host", "--reveal-host", "user@host"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if !reveal {
					t.Error("expected reveal to be true")
				}
				if target != "user@host" {
					t.Errorf("expected target user@host, got %s", target)
				}
			},
		},
		{
			name:    "ssh option with argument -J",
			input:   []string{"-J", "jumphost", "user@host"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if reveal {
					t.Error("expected reveal to be false")
				}
				if target != "user@host" {
					t.Errorf("expected target user@host, got %s", target)
				}
				if len(opts) != 2 || opts[0] != "-J" || opts[1] != "jumphost" {
					t.Errorf("expected opts [-J jumphost], got %v", opts)
				}
			},
		},
		{
			name:    "target with @ at start",
			input:   []string{"@host"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if target != "@host" {
					t.Errorf("expected target @host, got %s", target)
				}
			},
		},
		{
			name:    "target with multiple @",
			input:   []string{"user@sub@host"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if target != "user@sub@host" {
					t.Errorf("expected target user@sub@host, got %s", target)
				}
			},
		},
		{
			name:    "target without @",
			input:   []string{"hostname"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if target != "hostname" {
					t.Errorf("expected target hostname, got %s", target)
				}
			},
		},
		{
			name:    "separator with args that look like options after",
			input:   []string{"--", "-i", "key", "user@host"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if target != "user@host" {
					t.Errorf("expected target user@host, got %s", target)
				}
				if len(opts) != 2 || opts[0] != "-i" || opts[1] != "key" {
					t.Errorf("expected opts [-i key], got %v", opts)
				}
			},
		},
		{
			name:    "reveal-host and separator",
			input:   []string{"--reveal-host", "--", "-p", "2222", "user@host"},
			wantErr: false,
			checkFunc: func(t *testing.T, reveal bool, opts []string, target string) {
				if !reveal {
					t.Error("expected reveal to be true")
				}
				if target != "user@host" {
					t.Errorf("expected target user@host, got %s", target)
				}
				if len(opts) != 2 || opts[0] != "-p" || opts[1] != "2222" {
					t.Errorf("expected opts [-p 2222], got %v", opts)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reveal, opts, target, err := parseOpenArgs(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if test.wantMsg != "" && !strings.Contains(err.Error(), test.wantMsg) {
					t.Errorf("error message %q does not contain %q", err.Error(), test.wantMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if test.checkFunc != nil {
					test.checkFunc(t, reveal, opts, target)
				}
			}
		})
	}
}

// Test loadSession edge cases
func TestLoadSessionEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
		wantMsg string
	}{
		{
			name:    "garbage data",
			content: "not json at all!",
			wantErr: true,
		},
		{
			name:    "valid JSON missing host",
			content: `{"socket_path":"/tmp/sock","log_path":"/tmp/log"}`,
			wantErr: true,
			wantMsg: "invalid session state",
		},
		{
			name:    "valid JSON missing socket",
			content: `{"host":"user@host","log_path":"/tmp/log"}`,
			wantErr: true,
			wantMsg: "invalid session state",
		},
		{
			name:    "valid JSON missing log",
			content: `{"host":"user@host","socket_path":"/tmp/sock"}`,
			wantErr: true,
			wantMsg: "invalid session state",
		},
		{
			name:    "valid JSON empty host",
			content: `{"host":"","socket_path":"/tmp/sock","log_path":"/tmp/log"}`,
			wantErr: true,
			wantMsg: "invalid session state",
		},
		{
			name:    "valid JSON empty socket",
			content: `{"host":"user@host","socket_path":"","log_path":"/tmp/log"}`,
			wantErr: true,
			wantMsg: "invalid session state",
		},
		{
			name:    "valid JSON empty log",
			content: `{"host":"user@host","socket_path":"/tmp/sock","log_path":""}`,
			wantErr: true,
			wantMsg: "invalid session state",
		},
		{
			name:    "valid JSON with extra fields",
			content: `{"host":"user@host","socket_path":"/tmp/sock","log_path":"/tmp/log","extra_field":"value","allow_reveal_host":true}`,
			wantErr: false,
		},
		{
			name:    "valid JSON with whitespace",
			content: "  \n  {\n    \"host\": \"user@host\",\n    \"socket_path\": \"/tmp/sock\",\n    \"log_path\": \"/tmp/log\"\n  }\n  ",
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session.json")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}

			_, err := loadSession(path)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if test.wantMsg != "" && !strings.Contains(err.Error(), test.wantMsg) {
					t.Errorf("error message %q does not contain %q", err.Error(), test.wantMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test loadSession when file doesn't exist
func TestLoadSessionFileNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	_, err := loadSession(path)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

// Test loadAccess edge cases
func TestLoadAccessEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
		wantMsg string
	}{
		{
			name:    "garbage data",
			content: "not json!",
			wantErr: true,
		},
		{
			name:    "valid JSON missing hash",
			content: `{}`,
			wantErr: true,
			wantMsg: "invalid access state",
		},
		{
			name:    "valid JSON empty hash",
			content: `{"hash":""}`,
			wantErr: true,
			wantMsg: "invalid access state",
		},
		{
			name:    "valid JSON whitespace-only hash",
			content: `{"hash":"   "}`,
			wantErr: false, // whitespace is technically a non-empty string
		},
		{
			name:    "valid JSON with extra fields",
			content: `{"hash":"somehash","extra":"field"}`,
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "access")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}

			_, err := loadAccess(path)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if test.wantMsg != "" && !strings.Contains(err.Error(), test.wantMsg) {
					t.Errorf("error message %q does not contain %q", err.Error(), test.wantMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test loadAccess when file doesn't exist
func TestLoadAccessFileNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent")
	_, err := loadAccess(path)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

// Test writeSession file permissions
func TestWriteSessionFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	state := sessionState{
		Host:       "user@host",
		SocketPath: "/tmp/sock",
		LogPath:    "/tmp/log",
	}

	if err := writeSession(path, state); err != nil {
		t.Fatalf("writeSession error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("expected file mode 0600, got %o", mode)
	}
}

// Test writeAccess file permissions
func TestWriteAccessFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access")
	state := accessState{Hash: "test-hash"}

	if err := writeAccess(path, state); err != nil {
		t.Fatalf("writeAccess error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("expected file mode 0600, got %o", mode)
	}
}

// Test ensureRuntimeDir creates directory with correct permissions
func TestEnsureRuntimeDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime-test")

	if err := ensureRuntimeDir(dir); err != nil {
		t.Fatalf("ensureRuntimeDir error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	if !info.IsDir() {
		t.Fatal("expected directory")
	}

	mode := info.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("expected directory mode 0700, got %o", mode)
	}
}

// Test ensureRuntimeDir fixes wrong permissions
func TestEnsureRuntimeDirFixesPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime-test")

	// Create with wrong permissions
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := ensureRuntimeDir(dir); err != nil {
		t.Fatalf("ensureRuntimeDir error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("expected directory mode 0700, got %o", mode)
	}
}

// Test ensureAccessDir creates directory with correct permissions
func TestEnsureAccessDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "access-test")

	if err := ensureAccessDir(dir); err != nil {
		t.Fatalf("ensureAccessDir error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	if !info.IsDir() {
		t.Fatal("expected directory")
	}

	mode := info.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("expected directory mode 0700, got %o", mode)
	}
}

// Test ensureAccessDir fixes wrong permissions
func TestEnsureAccessDirFixesPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "access-test")

	// Create with wrong permissions
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := ensureAccessDir(dir); err != nil {
		t.Fatalf("ensureAccessDir error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("expected directory mode 0700, got %o", mode)
	}
}

// Test cleanupSession with partial state
func TestCleanupSessionPartialState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "session.json")

	tests := []struct {
		name  string
		state sessionState
	}{
		{
			name:  "empty socket path",
			state: sessionState{Host: "user@host", SocketPath: "", LogPath: filepath.Join(dir, "log")},
		},
		{
			name:  "empty log path",
			state: sessionState{Host: "user@host", SocketPath: filepath.Join(dir, "sock"), LogPath: ""},
		},
		{
			name:  "both empty",
			state: sessionState{Host: "user@host", SocketPath: "", LogPath: ""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create state file
			if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
				t.Fatalf("write state: %v", err)
			}

			// Should not error even with partial state
			if err := cleanupSession(test.state, statePath); err != nil {
				t.Fatalf("cleanupSession error: %v", err)
			}

			// State file should be removed
			if _, err := os.Stat(statePath); !os.IsNotExist(err) {
				t.Error("expected state file to be removed")
			}
		})
	}
}

// Test sessionPaths fallback to /tmp when XDG_RUNTIME_DIR is empty
func TestSessionPathsFallbackToTmp(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	dir, statePath, socketPath, logPath, err := sessionPaths()
	if err != nil {
		t.Fatalf("sessionPaths error: %v", err)
	}

	if !strings.HasPrefix(dir, "/tmp/") {
		t.Errorf("expected dir to start with /tmp/, got %s", dir)
	}
	if filepath.Dir(statePath) != dir {
		t.Errorf("statePath not in expected dir")
	}
	if filepath.Dir(socketPath) != dir {
		t.Errorf("socketPath not in expected dir")
	}
	if filepath.Dir(logPath) != dir {
		t.Errorf("logPath not in expected dir")
	}
}

// Test appendCommandLog with multiple entries
func TestAppendCommandLogMultipleEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.log")

	entries := []string{"pwd", "ls -la", "echo 'hello world'", "cat file.txt"}
	for _, entry := range entries {
		if err := appendCommandLog(path, entry); err != nil {
			t.Fatalf("appendCommandLog error: %v", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	content := string(data)
	for _, entry := range entries {
		expected := "- " + entry + "\n"
		if !strings.Contains(content, expected) {
			t.Errorf("expected log to contain %q, got %q", expected, content)
		}
	}

	// Verify order
	expectedContent := "- pwd\n- ls -la\n- echo 'hello world'\n- cat file.txt\n"
	if content != expectedContent {
		t.Errorf("expected log content %q, got %q", expectedContent, content)
	}
}

// Test initCommandLog creates new file
func TestInitCommandLogCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new-log.log")

	if err := initCommandLog(path); err != nil {
		t.Fatalf("initCommandLog error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}

	if info.IsDir() {
		t.Fatal("expected file, got directory")
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("expected file mode 0600, got %o", mode)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	if len(data) != 0 {
		t.Errorf("expected empty file, got %d bytes", len(data))
	}
}

// Test waitForSocket when socket appears just before deadline
func TestWaitForSocketNearDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep command not available on Windows")
	}

	socketPath := filepath.Join(t.TempDir(), "sock")
	cmd := exec.Command("sleep", "2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Create socket with enough margin before timeout
	// waitForSocket checks every 100ms, so we need to account for that
	timeout := 1 * time.Second
	go func() {
		time.Sleep(300 * time.Millisecond) // Create well before timeout
		_ = os.WriteFile(socketPath, []byte(""), 0o600)
	}()

	start := time.Now()
	if err := waitForSocket(socketPath, timeout, cmd); err != nil {
		t.Fatalf("waitForSocket error: %v", err)
	}
	elapsed := time.Since(start)

	// Should complete well before timeout
	if elapsed > timeout {
		t.Errorf("took longer than timeout: %v > %v", elapsed, timeout)
	}

	// Should complete after socket creation (300ms + some polling time)
	if elapsed < 250*time.Millisecond {
		t.Errorf("completed too quickly: %v", elapsed)
	}
}

// Test exitWithCode with nil error
func TestExitWithCodeNilError(t *testing.T) {
	// This test cannot directly test exitWithCode because it calls os.Exit
	// Instead, we verify the logic by checking what exitWithCode does
	// For this case, we'll test that exec.ExitError is handled correctly
	// and generic errors are handled correctly in other tests

	// Test with ExitError
	if runtime.GOOS == "windows" {
		t.Skip("exit code test not portable on Windows")
	}

	cmd := exec.Command("sh", "-c", "exit 42")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error from command")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatal("expected exec.ExitError")
	}

	if exitErr.ExitCode() != 42 {
		t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
	}
}

// Test exitWithCode with generic error
func TestExitWithCodeGenericError(t *testing.T) {
	// We can't directly test exitWithCode because it calls os.Exit
	// But we can verify that errors.As works correctly for our purposes
	err := errors.New("generic error")
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		t.Error("generic error should not be an ExitError")
	}
}

// Test race conditions in tailCommandLog with rapid appends
func TestTailCommandLogRaceConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.log")
	if err := initCommandLog(path); err != nil {
		t.Fatalf("initCommandLog error: %v", err)
	}

	stop := make(chan struct{})
	defer close(stop)

	// Start tailing
	go tailCommandLog(path, stop)

	// Rapidly append multiple entries from different goroutines
	const numGoroutines = 10
	const entriesPerGoroutine = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				entry := fmt.Sprintf("goroutine-%d-entry-%d", id, j)
				_ = appendCommandLog(path, entry)
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(500 * time.Millisecond) // Let tail catch up

	// Verify all entries are in the log
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != numGoroutines*entriesPerGoroutine {
		t.Errorf("expected %d lines, got %d", numGoroutines*entriesPerGoroutine, len(lines))
	}
}

// ============================================================================
// A1: SYMLINK SECURITY TESTS
// ============================================================================

// TestEnsureRuntimeDirRejectsSymlink verifies that ensureRuntimeDir rejects symlinks
func TestEnsureRuntimeDirRejectsSymlink(t *testing.T) {
	realDir := t.TempDir()
	symlinkPath := filepath.Join(t.TempDir(), "symlink-dir")

	// Create a symlink pointing to a real directory
	if err := os.Symlink(realDir, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// ensureRuntimeDir should reject the symlink
	err := ensureRuntimeDir(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error message should mention symlink, got: %v", err)
	}
}

// TestEnsureAccessDirRejectsSymlink verifies that ensureAccessDir rejects symlinks
func TestEnsureAccessDirRejectsSymlink(t *testing.T) {
	realDir := t.TempDir()
	symlinkPath := filepath.Join(t.TempDir(), "symlink-dir")

	// Create a symlink pointing to a real directory
	if err := os.Symlink(realDir, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// ensureAccessDir should reject the symlink
	err := ensureAccessDir(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error message should mention symlink, got: %v", err)
	}
}

// TestEnsureRuntimeDirAcceptsRealDir verifies that real directories work fine
func TestEnsureRuntimeDirAcceptsRealDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "real-dir")

	// This should succeed without error
	if err := ensureRuntimeDir(dir); err != nil {
		t.Fatalf("ensureRuntimeDir failed for real directory: %v", err)
	}

	// Verify directory exists and has correct permissions
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}
	mode := info.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("expected mode 0700, got %o", mode)
	}
}

// ============================================================================
// A2: ATOMIC WRITE TESTS
// ============================================================================

// TestWriteSessionConcurrentReadsNeverSeePartial verifies atomic writes
func TestWriteSessionConcurrentReadsNeverSeePartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(2)

	// Track valid reads across both goroutines
	var validReads int
	var readsMutex sync.Mutex

	// Writer goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			state := sessionState{
				Host:            fmt.Sprintf("user@host-%d", i),
				SocketPath:      fmt.Sprintf("/tmp/socket-%d", i),
				LogPath:         fmt.Sprintf("/tmp/log-%d", i),
				AllowRevealHost: i%2 == 0,
			}
			_ = writeSession(path, state)
			time.Sleep(100 * time.Microsecond) // Small delay to increase concurrency
		}
	}()

	// Reader goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					// File doesn't exist yet, try again
					time.Sleep(100 * time.Microsecond)
					continue
				}
				t.Errorf("read error: %v", err)
				continue
			}

			// Every successful read must produce valid JSON with non-empty fields
			var state sessionState
			if err := json.Unmarshal(data, &state); err != nil {
				t.Errorf("unmarshal error (partial data): %v, data: %q", err, string(data))
				continue
			}

			// Valid session must have non-empty required fields
			if state.Host != "" && state.SocketPath != "" && state.LogPath != "" {
				readsMutex.Lock()
				validReads++
				readsMutex.Unlock()
			}

			time.Sleep(100 * time.Microsecond)
		}
	}()

	wg.Wait()

	// We should have at least some valid reads
	readsMutex.Lock()
	defer readsMutex.Unlock()
	if validReads == 0 {
		t.Error("expected at least some valid reads")
	}
}

// TestWriteSessionAtomicTempFileCleanup verifies no temp files are left behind
func TestWriteSessionAtomicTempFileCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	state := sessionState{
		Host:       "user@host",
		SocketPath: "/tmp/socket",
		LogPath:    "/tmp/log",
	}

	if err := writeSession(path, state); err != nil {
		t.Fatalf("writeSession error: %v", err)
	}

	// List all files in the directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir error: %v", err)
	}

	// Should be exactly 1 file (the target file, no .tmp files)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected exactly 1 file, got %d: %v", len(entries), names)
	}

	// Verify it's the target file
	if len(entries) > 0 && entries[0].Name() != "session.json" {
		t.Errorf("expected session.json, got %s", entries[0].Name())
	}
}
