//! What an event records, in the words Sootmark's syslog reader uses for
//! the same things: commands run, logins and failed logins (over ssh or
//! not), sudo commands, sessions, account and group changes, passwords
//! changed, and network connections.

use std::net::IpAddr;

use crate::syscall::id;
use crate::{Event, Record, SocketAddress, Syscall};

/// What `acct` holds when sshd was asked for an account that doesn't exist.
const INVALID_USER: &str = "(invalid user)";

/// An account or group: its id, its name, or both. Raw logs give ids where
/// the kernel writes them (`auid=1000`) and names where programs do
/// (`acct="alice"`); an enriched log adds the names of the ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The uid or gid.
    pub id: Option<u32>,
    /// The name.
    pub name: Option<String>,
}

/// What an event records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activity {
    /// `command executed`, `network connect`, `ssh login`, `ssh failed
    /// login`, `login`, `failed login`, `authentication`, `failed
    /// authentication`, `sudo`, `session opened`, `session closed`, `user
    /// added`, `user deleted`, `user changed`, `group added`, `group
    /// deleted`, `group changed`, `password changed`.
    pub action: &'static str,
    /// Whether it succeeded (a system call's `success`, a program's `res`).
    pub success: Option<bool>,
    /// The login user (`auid`): who logged in, kept across `su` and `sudo`;
    /// in an investigation, the account that matters. `None` when unset
    /// (daemons, and before a login completes).
    pub login_user: Option<Account>,
    /// The account acted as (`uid`): the one running the command.
    pub user: Option<Account>,
    /// The account acted on: the one logging in, added, deleted, changed.
    pub account: Option<Account>,
    /// For a login: the account asked for doesn't exist (its name isn't
    /// recorded).
    pub invalid_user: bool,
    /// The group added, deleted, changed, or a user was added to.
    pub group: Option<Account>,
    /// Where a login came from (`addr`), normalised.
    pub source_ip: Option<String>,
    /// Where a connection went.
    pub destination_ip: Option<String>,
    /// Its port.
    pub destination_port: Option<u16>,
    /// The command line: the one run (`command executed`, `sudo`), or the
    /// connecting process's (`network connect`). For an exec that failed,
    /// the program it tried to run.
    pub command: Option<String>,
    /// The working directory.
    pub cwd: Option<String>,
    /// The program that did it, or recorded it (`/usr/sbin/sshd`).
    pub exe: Option<String>,
    /// The terminal (`pts0`, `/dev/pts/1`, `ssh`, `cron`).
    pub terminal: Option<String>,
    /// The login session.
    pub session: Option<u32>,
}

impl Activity {
    fn new(action: &'static str) -> Self {
        Self {
            action,
            success: None,
            login_user: None,
            user: None,
            account: None,
            invalid_user: false,
            group: None,
            source_ip: None,
            destination_ip: None,
            destination_port: None,
            command: None,
            cwd: None,
            exe: None,
            terminal: None,
            session: None,
        }
    }
}

/// What `event` records, when it's one of the [`Activity`] actions. A
/// system call is read from x86_64 numbers, or from an enriched log's
/// names; credentials (`CRED_*`) and other records stay plain events.
#[must_use]
pub fn classify(event: &Event) -> Option<Activity> {
    event
        .syscall()
        .and_then(|syscall| system_call(event, &syscall))
        .or_else(|| event.records.iter().find_map(program_record))
}

/// `execve` and `connect` (to an IP address).
fn system_call(event: &Event, syscall: &Syscall) -> Option<Activity> {
    let record = event.record("SYSCALL")?;
    let mut activity = match syscall.name? {
        "execve" | "execveat" => {
            let mut activity = Activity::new("command executed");
            // An exec that failed writes no EXECVE: what it tried to run
            // is the first path.
            activity.command = match &event.arguments {
                Some(arguments) if !arguments.is_empty() => Some(arguments.join(" ")),
                _ => event.paths().next().map(str::to_owned),
            };
            activity.cwd = event.cwd().map(str::to_owned);
            activity
        }
        "connect" => {
            let Some(SocketAddress::Inet(address)) = event.socket_address() else {
                return None;
            };
            let mut activity = Activity::new("network connect");
            activity.destination_ip = Some(address.ip().to_string());
            activity.destination_port = Some(address.port());
            activity.command = event.command_line();
            activity
        }
        _ => return None,
    };
    activity.success = syscall.success;
    activity.login_user = account(record, "auid", "AUID");
    activity.user = account(record, "uid", "UID");
    activity.exe = syscall.exe.map(str::to_owned);
    activity.terminal = syscall.tty.map(str::to_owned);
    activity.session = syscall.session;
    Some(activity)
}

/// The records programs write: sshd, login, sudo, PAM, the account tools.
fn program_record(record: &Record) -> Option<Activity> {
    let success = record.get("res").and_then(result);
    let outcome = |done, failed| if success == Some(false) { failed } else { done };
    let action = match record.kind.as_str() {
        "USER_LOGIN" if from_sshd(record) => outcome("ssh login", "ssh failed login"),
        "USER_LOGIN" => outcome("login", "failed login"),
        "USER_AUTH" => outcome("authentication", "failed authentication"),
        "USER_CMD" => "sudo",
        "USER_START" => "session opened",
        "USER_END" => "session closed",
        "ADD_USER" => "user added",
        "DEL_USER" => "user deleted",
        "USER_MGMT" | "CHUSER_ID" | "ACCT_LOCK" | "ACCT_UNLOCK" => "user changed",
        "USER_CHAUTHTOK" => "password changed",
        "ADD_GROUP" => "group added",
        "DEL_GROUP" => "group deleted",
        "GRP_MGMT" | "CHGRP_ID" => "group changed",
        _ => return None,
    };
    let mut activity = Activity::new(action);
    activity.success = success;
    activity.login_user = account(record, "auid", "AUID");
    activity.user = account(record, "uid", "UID");
    if about_a_group(&record.kind) {
        activity.group = acted_on(record);
    } else {
        activity.account = acted_on(record);
        activity.group = known(record.get("grp")).map(|name| Account {
            id: None,
            name: Some(name.to_owned()),
        });
    }
    activity.invalid_user = record.get("acct") == Some(INVALID_USER);
    activity.source_ip = record
        .get("addr")
        .and_then(|a| a.parse::<IpAddr>().ok())
        .map(|a| a.to_string());
    activity.command = record.get("cmd").map(str::to_owned);
    activity.cwd = record.get("cwd").map(str::to_owned);
    activity.exe = record.get("exe").map(str::to_owned);
    activity.terminal = known(record.get("terminal")).map(str::to_owned);
    activity.session = id(record, "ses");
    Some(activity)
}

fn about_a_group(kind: &str) -> bool {
    matches!(kind, "ADD_GROUP" | "DEL_GROUP" | "GRP_MGMT" | "CHGRP_ID")
}

/// `/usr/sbin/sshd`, and since OpenSSH 9.8 `sshd-session` and `sshd-auth`.
fn from_sshd(record: &Record) -> bool {
    record
        .get("exe")
        .and_then(|exe| exe.rsplit('/').next())
        .is_some_and(|name| name.starts_with("sshd"))
}

/// `res=`: `success`/`failed` in programs' records, `1`/`0` in the kernel's.
fn result(value: &str) -> Option<bool> {
    match value {
        "success" | "yes" | "1" => Some(true),
        "failed" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// `?` is what programs write for nothing.
fn known(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "?")
}

/// The account an id field names, with the enriched log's name for it.
fn account(record: &Record, field: &str, interpretation: &str) -> Option<Account> {
    id(record, field).map(|id| Account {
        id: Some(id),
        name: interpreted_name(record, interpretation).map(str::to_owned),
    })
}

/// The enriched log's name for an id: not `unset`, nor `unknown(1001)`
/// (an id the host had no name for).
fn interpreted_name<'a>(record: &'a Record, interpretation: &str) -> Option<&'a str> {
    record
        .interpretation(interpretation)
        .filter(|n| *n != "unset" && !n.starts_with("unknown("))
}

/// The account a program's record is about: `acct="bob"`, or `id=1001`
/// (named `ID="bob"` in an enriched log).
fn acted_on(record: &Record) -> Option<Account> {
    let name = known(record.get("acct"))
        .filter(|a| *a != INVALID_USER)
        .or_else(|| interpreted_name(record, "ID"));
    let id = id(record, "id");
    (name.is_some() || id.is_some()).then(|| Account {
        id,
        name: name.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    fn activity(line: &str) -> Activity {
        classify(&parse(line.as_bytes()).events[0]).unwrap()
    }

    fn named(id: u32, name: &str) -> Account {
        Account {
            id: Some(id),
            name: Some(name.to_owned()),
        }
    }

    #[test]
    fn logins() {
        let failed = activity("type=USER_LOGIN msg=audit(1492896301.818:19955): pid=12635 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=28696E76616C6964207573657229 exe=\"/usr/sbin/sshd\" hostname=? addr=179.38.151.221 terminal=sshd res=failed'");
        assert_eq!(failed.action, "ssh failed login");
        assert!(failed.invalid_user);
        assert_eq!((failed.account, failed.login_user), (None, None));
        assert_eq!(failed.source_ip.as_deref(), Some("179.38.151.221"));
        let login = activity("type=USER_LOGIN msg=audit(1791060454.481:32260): pid=1928542 uid=0 auid=1001 ses=1254 subj=unconfined msg='op=login id=1001 exe=\"/usr/lib/openssh/sshd-session\" hostname=127.0.0.1 addr=127.0.0.1 terminal=/dev/pts/11 res=success'\x1dUID=\"root\" AUID=\"sootmarktest\" ID=\"sootmarktest\"");
        assert_eq!(
            (login.action, login.success, login.session),
            ("ssh login", Some(true), Some(1254))
        );
        assert_eq!(login.account, Some(named(1001, "sootmarktest")));
        assert_eq!(login.login_user, Some(named(1001, "sootmarktest")));
        assert_eq!(login.user, Some(named(0, "root")));
        assert_eq!(login.terminal.as_deref(), Some("/dev/pts/11"));
        let console = activity("type=USER_LOGIN msg=audit(1.000:1): pid=1 uid=0 auid=1000 ses=2 msg='op=login acct=\"alice\" exe=\"/usr/bin/login\" hostname=? addr=? terminal=tty1 res=success'");
        assert_eq!((console.action, console.source_ip), ("login", None));
    }

    #[test]
    fn sudo_and_accounts() {
        let sudo = activity("type=USER_CMD msg=audit(1488862769.030:19469538): user pid=3027 uid=497 auid=700 ses=11988 msg='cwd=\"/\" cmd=2F7573722F6C696236342F6E6167696F732F706C7567696E732F636865636B5F617374657269736B5F7369705F7065657273202D7020313037 terminal=? res=success'");
        assert_eq!(sudo.action, "sudo");
        assert_eq!(
            sudo.command.as_deref(),
            Some("/usr/lib64/nagios/plugins/check_asterisk_sip_peers -p 107")
        );
        assert_eq!((sudo.cwd.as_deref(), sudo.terminal), (Some("/"), None));
        assert_eq!(sudo.login_user.and_then(|a| a.id), Some(700));
        let group = activity("type=ADD_GROUP msg=audit(1791060246.189:210): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='op=add-group id=1001 exe=\"/usr/sbin/groupadd\" hostname=? addr=? terminal=? res=success'\x1dUID=\"root\" AUID=\"unset\" ID=\"sootmarkops\"");
        assert_eq!(group.action, "group added");
        assert_eq!(group.group, Some(named(1001, "sootmarkops")));
        assert_eq!((group.account, group.login_user), (None, None));
        let member = activity("type=USER_MGMT msg=audit(1.000:1): pid=1 uid=0 auid=1000 ses=1 msg='op=add-user-to-group grp=\"adm\" acct=\"bob\" exe=\"/usr/sbin/usermod\" hostname=? addr=? terminal=? res=success'");
        assert_eq!(member.action, "user changed");
        assert_eq!(member.group.and_then(|g| g.name).as_deref(), Some("adm"));
        assert_eq!(member.account.and_then(|a| a.name).as_deref(), Some("bob"));
        let removed = activity("type=DEL_USER msg=audit(1783478974.807:508): pid=3924 uid=0 auid=1000 ses=17 msg='op=deleting-user-not-found acct=\"specimenuser\" exe=\"/usr/sbin/userdel\" hostname=? addr=? terminal=? res=failed'");
        assert_eq!(
            (removed.action, removed.success),
            ("user deleted", Some(false))
        );
    }

    #[test]
    fn commands_and_connections() {
        let log = parse(b"type=SYSCALL msg=audit(1492037289.295:58): arch=c000003e syscall=42 success=no exit=-115 a0=6 items=0 ppid=1 pid=1172 auid=4294967295 uid=0 tty=(none) ses=4294967295 comm=\"google_accounts\" exe=2F7573722F62696E2F707974686F6E322E37 key=(null)\n\
            type=SOCKADDR msg=audit(1492037289.295:58): saddr=02000050A9FEA9FE0000000000000000\n\
            type=SYSCALL msg=audit(1.000:2): arch=c000003e syscall=42 success=yes exit=0 auid=1000 uid=1000\n\
            type=SOCKADDR msg=audit(1.000:2): saddr=01002F6465762F6C6F6700\n");
        let connect = classify(&log.events[0]).unwrap();
        assert_eq!(
            (
                connect.action,
                connect.success,
                connect.destination_ip.as_deref(),
                connect.destination_port
            ),
            (
                "network connect",
                Some(false),
                Some("169.254.169.254"),
                Some(80)
            )
        );
        assert_eq!(connect.exe.as_deref(), Some("/usr/bin/python2.7"));
        assert_eq!((connect.login_user, connect.terminal), (None, None));
        // A Unix socket isn't the network.
        assert_eq!(classify(&log.events[1]), None);
        let exec = activity("type=SYSCALL msg=audit(1.000:3): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 tty=pts1 ses=3 exe=\"/usr/bin/cat\"");
        assert_eq!(
            (exec.action, exec.terminal.as_deref(), exec.command),
            ("command executed", Some("pts1"), None)
        );
        assert_eq!(exec.login_user.and_then(|a| a.id), Some(1000));
        // Another architecture's numbers aren't guessed.
        let i386 =
            parse(b"type=SYSCALL msg=audit(1.000:4): arch=40000003 syscall=11 success=yes\n");
        assert_eq!(classify(&i386.events[0]), None);
    }
}
