package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
