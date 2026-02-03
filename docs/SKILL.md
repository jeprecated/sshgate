# sshgate Skill Guide

This document describes how an agent should use the `sshgate` CLI.

## Overview

`sshgate` provides a user-gated SSH proxy. A human opens an SSH session first, and only then an agent can run commands through the established SSH control socket.

## Commands

### Allowed commands

Agents are only allowed to use the commands below. All other `sshgate` commands are human-only and forbidden for agents.

### run

Runs a command on the active session using separate arguments (no string concatenation).

```sh
sshgate run COMMAND [ARG...]
```

To run a shell pipeline or operators like `&&`, use the shell mode:

```sh
sshgate run -- "ls && pwd"
```

- Must be run after `open` is active.
- If there is no active session, `run` exits with a clear error.
- Exit code is the remote command's exit code.

### close

Closes the active session and cleans up local state.

```sh
sshgate close
```

- If no session is active, `close` exits with an error.

### status

Reports whether a session is active.

```sh
sshgate status
```

- Prints `active` when connected, otherwise `inactive`.
- If the session was opened with `--reveal-host`, output becomes `active: user@host`.
- Exit code is `0` when active, `1` when inactive.

## Notes

- Do not attempt to bypass the human gate; the session is intentionally human-gated.
