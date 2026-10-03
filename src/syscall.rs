//! What an event's `SYSCALL` record says, and where its `SOCKADDR` points.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{decode, Event, Record};

/// `AUDIT_ARCH_*` values and their names.
const ARCHITECTURES: [(&str, &str); 4] = [
    ("c000003e", "x86_64"),
    ("40000003", "i386"),
    ("c00000b7", "aarch64"),
    ("40000028", "arm"),
];

/// x86_64 system calls an investigation asks about; others are left as
/// numbers (an enriched log names them all).
const X86_64: [(u32, &str); 53] = [
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (46, "sendmsg"),
    (49, "bind"),
    (50, "listen"),
    (56, "clone"),
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (62, "kill"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (90, "chmod"),
    (91, "fchmod"),
    (92, "chown"),
    (93, "fchown"),
    (94, "lchown"),
    (101, "ptrace"),
    (105, "setuid"),
    (106, "setgid"),
    (113, "setreuid"),
    (114, "setregid"),
    (117, "setresuid"),
    (119, "setresgid"),
    (165, "mount"),
    (166, "umount2"),
    (175, "init_module"),
    (176, "delete_module"),
    (257, "openat"),
    (258, "mkdirat"),
    (260, "fchownat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (265, "linkat"),
    (266, "symlinkat"),
    (268, "fchmodat"),
    (288, "accept4"),
    (313, "finit_module"),
    (316, "renameat2"),
    (322, "execveat"),
    (435, "clone3"),
    (437, "openat2"),
];

/// A login or user id that was never set (`auid` before any login).
const UNSET: u32 = u32::MAX;

/// What a `SYSCALL` record says. Ids are `None` when not written, or unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syscall<'a> {
    /// `x86_64`, `i386`, `aarch64`, `arm`; the `AUDIT_ARCH` value as
    /// written for others.
    pub arch: Option<&'a str>,
    /// The system call's number, for its architecture.
    pub number: Option<u32>,
    /// Its name: the enriched log's, or from a short x86_64 table.
    pub name: Option<&'a str>,
    /// Whether it succeeded.
    pub success: Option<bool>,
    /// What it returned (`-13`: permission denied).
    pub exit: Option<i64>,
    /// The process.
    pub pid: Option<u32>,
    /// Its parent.
    pub ppid: Option<u32>,
    /// The login uid: who logged in, kept across `su` and `sudo`.
    pub auid: Option<u32>,
    /// The real uid.
    pub uid: Option<u32>,
    /// The effective uid.
    pub euid: Option<u32>,
    /// The real gid.
    pub gid: Option<u32>,
    /// The login session.
    pub session: Option<u32>,
    /// The terminal (`pts0`), when there is one.
    pub tty: Option<&'a str>,
    /// The process's name (16 bytes at most).
    pub comm: Option<&'a str>,
    /// Its executable.
    pub exe: Option<&'a str>,
    /// The keys of the audit rules that matched.
    pub keys: Vec<&'a str>,
}

impl Event {
    /// What the `SYSCALL` record says.
    #[must_use]
    pub fn syscall(&self) -> Option<Syscall<'_>> {
        let record = self.record("SYSCALL")?;
        let written_arch = record.get("arch");
        let arch = record.interpretation("ARCH").or_else(|| {
            written_arch.map(|a| {
                ARCHITECTURES
                    .iter()
                    .find_map(|&(value, name)| (value == a).then_some(name))
                    .unwrap_or(a)
            })
        });
        let number = record.get("syscall").and_then(|n| n.parse().ok());
        let name = record.interpretation("SYSCALL").or_else(|| {
            let number = number.filter(|_| arch == Some("x86_64"))?;
            X86_64
                .iter()
                .find_map(|&(n, name)| (n == number).then_some(name))
        });
        Some(Syscall {
            arch,
            number,
            name,
            success: record.get("success").and_then(yes_no),
            exit: record.get("exit").and_then(|e| e.parse().ok()),
            pid: id(record, "pid"),
            ppid: id(record, "ppid"),
            auid: id(record, "auid"),
            uid: id(record, "uid"),
            euid: id(record, "euid"),
            gid: id(record, "gid"),
            session: id(record, "ses"),
            tty: record.get("tty").filter(|t| *t != "(none)"),
            comm: record.get("comm"),
            exe: record.get("exe"),
            keys: record
                .get("key")
                .filter(|k| *k != "(null)")
                .map(|k| k.split("\\x{01}").collect())
                .unwrap_or_default(),
        })
    }

    /// Where the `SOCKADDR` record points: its `saddr`, read.
    #[must_use]
    pub fn socket_address(&self) -> Option<SocketAddress> {
        socket_address(self.record("SOCKADDR")?.get("saddr")?)
    }
}

/// An id field: `None` when missing, unreadable, or unset.
pub(crate) fn id(record: &Record, name: &str) -> Option<u32> {
    record
        .get(name)?
        .parse()
        .ok()
        .filter(|&id: &u32| id != UNSET)
}

fn yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// A socket address (`struct sockaddr`, as the kernel copied it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    /// IPv4 or IPv6, with the port.
    Inet(SocketAddr),
    /// A Unix socket's path; an abstract one starts with `@`.
    Unix(String),
    /// A netlink socket (the kernel's own messages).
    Netlink,
    /// Another family, by number.
    Other(u16),
}

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const AF_NETLINK: u16 = 16;

/// `saddr`'s hex: the family in the host's order (little-endian, as on
/// x86 and ARM), the port and address in network order.
fn socket_address(saddr: &str) -> Option<SocketAddress> {
    let bytes = decode::hex_bytes(saddr)?;
    let family = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    let port = || Some(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]));
    let take = |range: std::ops::Range<usize>| bytes.get(range);
    Some(match family {
        AF_INET => {
            let ip: [u8; 4] = take(4..8)?.try_into().ok()?;
            SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip),
                port()?,
            )))
        }
        AF_INET6 => {
            let flow: [u8; 4] = take(4..8)?.try_into().ok()?;
            let ip: [u8; 16] = take(8..24)?.try_into().ok()?;
            let scope = take(24..28)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u32::from_le_bytes);
            SocketAddress::Inet(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port()?,
                u32::from_be_bytes(flow),
                scope,
            )))
        }
        AF_UNIX => SocketAddress::Unix(unix_path(take(2..bytes.len())?)),
        AF_NETLINK => SocketAddress::Netlink,
        other => SocketAddress::Other(other),
    })
}

/// A path ends at its NUL; an abstract name starts with one.
fn unix_path(path: &[u8]) -> String {
    let until_nul = |bytes: &[u8]| {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        decode::text(&bytes[..end])
    };
    match path.split_first() {
        Some((0, name)) => format!("@{}", until_nul(name)),
        _ => until_nul(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(saddr: &str) -> Option<SocketAddress> {
        socket_address(saddr)
    }

    #[test]
    fn socket_addresses() {
        assert_eq!(
            address("02000050A9FEA9FE0000000000000000"),
            Some(SocketAddress::Inet("169.254.169.254:80".parse().unwrap()))
        );
        assert_eq!(
            address("0A000016000000000000000000000000000000000000000100000000"),
            Some(SocketAddress::Inet("[::1]:22".parse().unwrap()))
        );
        assert_eq!(
            address("01002F6465762F6C6F6700000000"),
            Some(SocketAddress::Unix("/dev/log".to_owned()))
        );
        assert_eq!(
            address("0100006E6F746966790000"),
            Some(SocketAddress::Unix("@notify".to_owned()))
        );
        assert_eq!(
            address("100000000000000000000000"),
            Some(SocketAddress::Netlink)
        );
        assert_eq!(address("1100"), Some(SocketAddress::Other(17)));
        // Cut short, odd, empty.
        for damaged in ["0200005", "02000050A9FE", "", "02"] {
            assert_eq!(address(damaged), None, "{damaged}");
        }
    }

    #[test]
    fn x86_64_table_is_sorted_and_unique() {
        assert!(X86_64.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
