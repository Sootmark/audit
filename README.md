# audit

Linux audit logs (`/var/log/audit/audit.log` and its rotations `audit.log.1`, …) as auditd writes them, raw or enriched, and what they record: commands run, logins, sudo commands, account changes, connections. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-audit = "0.1"
```

```rust
let log = audit::parse(&std::fs::read("/var/log/audit/audit.log")?);
for event in &log.events {
    if let Some(activity) = audit::classify(event) {
        let login = activity.login_user.and_then(|a| a.id);
        println!("{} {} auid={login:?} {:?}", event.time, activity.action, activity.command);
    }
}
```

## What you get

- `parse(bytes)`: every record (`type=SYSCALL msg=audit(1783478974.713:500): …`, maybe after `node=<host>`), gathered into events by time and serial number, even when other records come between them. Each event has its time (UTC, to the millisecond), serial, node and records; each record its type and fields, in order.
- Values decoded: quotes taken off; what auditd hex-encodes (values with spaces, quotes or bytes outside printable ASCII: `proctitle`, `EXECVE`'s arguments, `cmd`, `exe`, `name`, `acct`, rule keys, …) turned back into text, what isn't text escaped as `\x{ff}`; a program's nested `msg='…'` read as the record's own fields; an enriched log's interpretations (`AUID="alice"`, `SYSCALL=execve`) kept apart. SELinux access decisions keep their result and permissions (`seresult`, `seperms`).
- Per event: the program's arguments (pieces of long ones, `aN[0]`, `aN[1]`, …, joined as bytes then decoded), the command line, the process title, the working directory, the paths; the system call (architecture, number, name from the enriched log or a short x86_64 table, success, exit, pid, ppid, auid, uid, euid, gid, session, tty, comm, exe, rule keys); the socket address (IPv4, IPv6 with port, Unix path, netlink).
- `classify(event)`, in the words of `sootmark-syslog`: commands executed (command line, working directory, executable; for a failed exec, what it tried to run), network connections (address and port), ssh logins and failed logins (account, invalid user flagged, source address, terminal), other logins, authentications, sudo commands (command and directory), sessions opened and closed, users and groups added, deleted and changed, passwords changed. Each with the login user (`auid`: who logged in, kept across `su` and `sudo`), the user acting (`uid`), names when the log is enriched, and whether it succeeded.
- A line that isn't a record, hex that doesn't make whole bytes, an `EXECVE` without its arguments: reported in `problems`, never fatal.

Not yet: system call names for other architectures than x86_64 (unless the log is enriched), 32-bit calls on 64-bit machines, record types by number (`UNKNOWN[1323]` stays as written), keystrokes (`TTY`) shown as keys.

## How it's checked

- Against audit-userspace's own tools: every fixture's `ausearch --interpret` and `aureport` output, from audit 4.0.2 (`tests/oracle/`, `regenerate.sh`). The same events, times and record types; the same decoded values (process titles, arguments, paths, executables, commands, accounts, addresses, rule keys, system call names, socket addresses), over 5 000 of them; the same logins, authentications, account changes and system call names. Where a damaged line is read differently, the test says how and why.
- plaso's audit test files (Apache-2.0, `tests/fixtures/plaso/`), as plaso's own tests expect them.
- Elastic go-libaudit's test logs (Apache-2.0, `tests/fixtures/go-libaudit/`): RHEL 6 and 7, Ubuntu 14 to 17, interleaved events, a serial number wrapping around, old PAM records.
- A log recorded on a Debian 13 lab machine (`tests/fixtures/lab/`, with the scripts that made it): accounts created and deleted, commands with spaces, accents and a 9 000-byte argument, sudo, IPv4 and IPv6 connections, an ssh login with a key and a failed one.
- Property tests: arbitrary bytes and real logs damaged anywhere give events or problems, never a panic.

## Licence

MIT or Apache-2.0, at your option. The test files from plaso and go-libaudit are under the Apache licence 2.0 (their licences are next to them).
