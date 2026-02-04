package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const (
	appName           = "sshgate"
	stateFileName     = "session.json"
	socketFileName    = "control.sock"
	logFileName       = "commands.log"
	accessFileName    = "access"
	socketWaitTimeout = 10 * time.Second
)

var sshBinary = "ssh"
var version = "dev"

type sessionState struct {
	Host            string `json:"host"`
	SocketPath      string `json:"socket_path"`
	LogPath         string `json:"log_path"`
	AllowRevealHost bool   `json:"allow_reveal_host"`
}

type accessState struct {
	Hash string `json:"hash"`
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "open":
		runOpen(os.Args[2:])
	case "run":
		runRun(os.Args[2:])
	case "close":
		runClose(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Fprintln(os.Stdout, version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n", appName, os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, "%s - user-gated SSH proxy\n\n", appName)
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s init\n", appName)
	fmt.Fprintf(w, "  %s open [--reveal-host] [SSH_OPTS...] user@host\n", appName)
	fmt.Fprintf(w, "  %s run COMMAND [ARG...]\n", appName)
	fmt.Fprintf(w, "  %s run -- \"COMMAND STRING\"\n", appName)
	fmt.Fprintf(w, "  %s close\n", appName)
	fmt.Fprintf(w, "  %s status\n", appName)
	fmt.Fprintf(w, "  %s version\n", appName)
}

func runInit(args []string) {
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "%s: init does not take arguments\n", appName)
		os.Exit(2)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fatal(errors.New("init requires a TTY"))
	}

	accessDir, accessPath, err := accessPaths()
	if err != nil {
		fatal(err)
	}

	if _, err := os.Stat(accessPath); err == nil {
		fatal(fmt.Errorf("access already initialized. To reset, delete %s and re-run init", accessPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		fatal(err)
	}

	if err := ensureAccessDir(accessDir); err != nil {
		fatal(err)
	}

	password, err := promptPassword("New password: ")
	if err != nil {
		fatal(err)
	}
	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		fatal(err)
	}
	if password == "" {
		fatal(errors.New("password cannot be empty"))
	}
	if password != confirm {
		fatal(errors.New("passwords do not match"))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fatal(err)
	}

	state := accessState{Hash: string(hash)}
	if err := writeAccess(accessPath, state); err != nil {
		fatal(err)
	}

	fmt.Fprintln(os.Stdout, "Access initialized.")
}

func runOpen(args []string) {
	allowRevealHost, sshOpts, target, err := parseOpenArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		os.Exit(2)
	}

	if err := verifyAccess(); err != nil {
		fatal(err)
	}
	runtimeDir, statePath, socketPath, logPath, err := sessionPaths()
	if err != nil {
		fatal(err)
	}

	if err := ensureRuntimeDir(runtimeDir); err != nil {
		fatal(err)
	}

	existing, err := loadSession(statePath)
	if err == nil {
		active, _ := sessionActive(existing)
		if active {
			fmt.Fprintf(os.Stderr, "%s: session already open for %s\n", appName, existing.Host)
			os.Exit(1)
		}
		_ = cleanupSession(existing, statePath)
	}

	_ = syscall.Umask(0o077)
	sshArgs := []string{"-M", "-S", socketPath, "-N"}
	sshArgs = append(sshArgs, sshOpts...)
	sshArgs = append(sshArgs, target)
	cmd := sshCommand(sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fatal(err)
	}

	if err := waitForSocket(socketPath, socketWaitTimeout, cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		fatal(err)
	}

	state := sessionState{Host: target, SocketPath: socketPath, LogPath: logPath, AllowRevealHost: allowRevealHost}
	if err := writeSession(statePath, state); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		fatal(err)
	}

	if err := initCommandLog(state.LogPath); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		fatal(err)
	}

	fmt.Fprintf(os.Stdout, "Connected to %s\n", target)
	fmt.Fprintln(os.Stdout, "pwd:")
	if err := runRemoteCommand(state, []string{"pwd"}); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: initial pwd failed: %v\n", appName, err)
	}

	stopLog := make(chan struct{})
	go tailCommandLog(state.LogPath, stopLog)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signals
		_ = cmd.Process.Signal(sig)
	}()

	err = cmd.Wait()
	close(stopLog)
	_ = cleanupSession(state, statePath)
	exitWithCode(err)
}

func runRun(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "%s: run expects a command to execute\n", appName)
		os.Exit(2)
	}

	shellMode := false
	commandLine := ""
	if args[0] == "--" {
		shellMode = true
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "%s: run -- expects a command string\n", appName)
			os.Exit(2)
		}
		if len(args) == 2 {
			commandLine = args[1]
		} else {
			commandLine = shellJoin(args[1:])
		}
	}

	_, statePath, _, _, err := sessionPaths()
	if err != nil {
		fatal(err)
	}

	state, err := loadSession(statePath)
	if err != nil {
		noSessionError()
		os.Exit(1)
	}

	active, err := sessionActive(state)
	if err != nil || !active {
		noSessionError()
		os.Exit(1)
	}

	logLine := ""
	if shellMode {
		logLine = commandLine
	} else {
		logLine = strings.Join(args, " ")
	}
	if err := appendCommandLog(state.LogPath, logLine); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: failed to log command: %v\n", appName, err)
	}

	if shellMode {
		err = runRemoteShell(state, commandLine)
	} else {
		err = runRemoteCommand(state, args)
	}
	exitWithCode(err)
}

func runClose(args []string) {
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "%s: close does not take arguments\n", appName)
		os.Exit(2)
	}

	_, statePath, _, _, err := sessionPaths()
	if err != nil {
		fatal(err)
	}

	state, err := loadSession(statePath)
	if err != nil {
		noSessionError()
		os.Exit(1)
	}

	active, err := sessionActive(state)
	if err != nil || !active {
		noSessionError()
		_ = cleanupSession(state, statePath)
		os.Exit(1)
	}

	cmd := sshCommand("-S", state.SocketPath, "-O", "exit", state.Host)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	_ = cleanupSession(state, statePath)
}

func runStatus(args []string) {
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "%s: status does not take arguments\n", appName)
		os.Exit(2)
	}

	_, statePath, _, _, err := sessionPaths()
	if err != nil {
		fatal(err)
	}

	state, err := loadSession(statePath)
	if err != nil {
		fmt.Fprintln(os.Stdout, "inactive")
		os.Exit(1)
	}

	active, err := sessionActive(state)
	if err != nil || !active {
		_ = cleanupSession(state, statePath)
		fmt.Fprintln(os.Stdout, "inactive")
		os.Exit(1)
	}

	if state.AllowRevealHost {
		fmt.Fprintf(os.Stdout, "active: %s\n", state.Host)
		return
	}

	fmt.Fprintln(os.Stdout, "active")
}

func sessionPaths() (string, string, string, string, error) {
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime == "" {
		runtime = "/tmp"
	}

	dir := filepath.Join(runtime, fmt.Sprintf("%s-%d", appName, os.Getuid()))
	statePath := filepath.Join(dir, stateFileName)
	socketPath := filepath.Join(dir, socketFileName)
	logPath := filepath.Join(dir, logFileName)
	if len(socketPath) > 100 {
		return "", "", "", "", fmt.Errorf("%s: socket path too long: %s", appName, socketPath)
	}
	return dir, statePath, socketPath, logPath, nil
}

func accessPaths() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	accessDir := filepath.Join(home, ".sshgate")
	accessPath := filepath.Join(accessDir, accessFileName)
	return accessDir, accessPath, nil
}

func ensureRuntimeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func ensureAccessDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func loadSession(path string) (sessionState, error) {
	var state sessionState
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Host == "" || state.SocketPath == "" || state.LogPath == "" {
		return state, errors.New("invalid session state")
	}
	return state, nil
}

func loadAccess(path string) (accessState, error) {
	var state accessState
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Hash == "" {
		return state, errors.New("invalid access state")
	}
	return state, nil
}

func writeSession(path string, state sessionState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}

func writeAccess(path string, state accessState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}

func sessionActive(state sessionState) (bool, error) {
	cmd := sshCommand("-S", state.SocketPath, "-O", "check", state.Host)
	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func waitForSocket(path string, timeout time.Duration, cmd *exec.Cmd) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return errors.New("ssh exited before socket was ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s: timed out waiting for SSH control socket", appName)
}

func cleanupSession(state sessionState, statePath string) error {
	_ = os.Remove(statePath)
	if state.SocketPath != "" {
		_ = os.Remove(state.SocketPath)
	}
	if state.LogPath != "" {
		_ = os.Remove(state.LogPath)
	}
	return nil
}

func noSessionError() {
	fmt.Fprintf(os.Stderr, "%s: no active session. A human must open the gate first.\n", appName)
}

func verifyAccess() error {
	accessDir, accessPath, err := accessPaths()
	if err != nil {
		return err
	}

	state, err := loadAccess(accessPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("access not initialized. Run '%s init' first (human-only, not for agents)", appName)
		}
		return err
	}

	if err := ensureAccessDir(accessDir); err != nil {
		return err
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("access check requires a TTY")
	}

	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(state.Hash), []byte(password)); err != nil {
		return errors.New("access denied")
	}
	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(input), nil
}

func sshCommand(args ...string) *exec.Cmd {
	return exec.Command(sshBinary, args...)
}

func runRemoteCommand(state sessionState, args []string) error {
	commandLine := shellJoin(args)
	sshArgs := []string{"-S", state.SocketPath, state.Host, "--", commandLine}
	cmd := sshCommand(sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func initCommandLog(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

func appendCommandLog(path string, line string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	entry := "- " + line + "\n"
	_, err = file.WriteString(entry)
	return err
}

func tailCommandLog(path string, stop <-chan struct{}) {
	var offset int
	for {
		select {
		case <-stop:
			return
		case <-time.After(250 * time.Millisecond):
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) <= offset {
			continue
		}
		chunk := data[offset:]
		offset = len(data)
		fmt.Fprint(os.Stdout, string(chunk))
	}
}

func runRemoteShell(state sessionState, commandLine string) error {
	sshArgs := []string{"-S", state.SocketPath, state.Host, "--", "sh", "-c", commandLine}
	cmd := sshCommand(sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func shellJoin(args []string) string {
	escaped := make([]string, 0, len(args))
	for _, arg := range args {
		escaped = append(escaped, shellEscape(arg))
	}
	return strings.Join(escaped, " ")
}

func shellEscape(arg string) string {
	if arg == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
}

func parseOpenArgs(args []string) (bool, []string, string, error) {
	allowRevealHost := false
	sshOpts := make([]string, 0)
	remaining := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--reveal-host" {
			allowRevealHost = true
			continue
		}
		remaining = append(remaining, arg)
	}

	if len(remaining) == 0 {
		return false, nil, "", errors.New("open expects a target like user@host")
	}

	for i, arg := range remaining {
		if arg == "--" {
			remaining = append(remaining[:i], remaining[i+1:]...)
			break
		}
	}

	if len(remaining) < 1 {
		return false, nil, "", errors.New("open expects a target like user@host")
	}
	if len(remaining) == 1 {
		return allowRevealHost, nil, remaining[0], nil
	}

	sshOpts = remaining[:len(remaining)-1]
	target := remaining[len(remaining)-1]
	for i, opt := range sshOpts {
		if strings.HasPrefix(opt, "-") {
			continue
		}
		if i == 0 || !strings.HasPrefix(sshOpts[i-1], "-") {
			return false, nil, "", errors.New("open expects SSH options before the target (use -- to disambiguate)")
		}
	}
	return allowRevealHost, sshOpts, target, nil
}

func exitWithCode(err error) {
	if err == nil {
		os.Exit(0)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
	os.Exit(1)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
	os.Exit(1)
}
