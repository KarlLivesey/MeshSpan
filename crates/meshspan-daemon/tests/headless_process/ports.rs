// SPDX-License-Identifier: GPL-2.0-only

//! Listener candidates stay reserved across test processes and daemon restarts.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

const FIRST: u32 = 16_384;
const COUNT: u32 = 16_384;
static NEXT: AtomicU32 = AtomicU32::new(0);
static EPHEMERAL: OnceLock<Result<RangeInclusive<u16>, String>> = OnceLock::new();
// File locks are released by the OS on test-process exit, including a crash. Keep the
// files: unlinking a locked inode would allow a second allocator to lock its replacement.
static RESERVATIONS: Mutex<Vec<File>> = Mutex::new(Vec::new());

pub(super) fn tcp() -> io::Result<SocketAddr> {
    allocate(|address| TcpListener::bind(address)?.local_addr())
}

pub(super) fn udp() -> io::Result<SocketAddr> {
    allocate(|address| UdpSocket::bind(address)?.local_addr())
}

fn allocate(bind: impl Fn(SocketAddr) -> io::Result<SocketAddr>) -> io::Result<SocketAddr> {
    let ephemeral = EPHEMERAL
        .get_or_init(read_ephemeral_range)
        .as_ref()
        .map_err(|message| io::Error::other(message.clone()))?;
    for _ in 0..COUNT {
        let candidate = FIRST + NEXT.fetch_add(1, Ordering::Relaxed) % COUNT;
        let port = u16::try_from(candidate).map_err(io::Error::other)?;
        if ephemeral.contains(&port) {
            continue;
        }
        let Some(reservation) = reserve(port)? else {
            continue;
        };
        match bind(SocketAddr::from(([127, 0, 0, 1], port))) {
            Ok(address) => {
                RESERVATIONS
                    .lock()
                    .map_err(|_| io::Error::other("poisoned test port reservations"))?
                    .push(reservation);
                return Ok(address);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no test listener port outside the OS ephemeral range",
    ))
}

fn reserve(port: u16) -> io::Result<Option<File>> {
    // Shared by invocations of this checkout, including directly executed test binaries.
    // This reserves only test addresses, not a global test-suite lock.
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/headless-port-reservations");
    std::fs::create_dir_all(&directory)?;
    let reservation = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(port.to_string()))?;
    match reservation.try_lock() {
        Ok(()) => Ok(Some(reservation)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

fn read_ephemeral_range() -> Result<RangeInclusive<u16>, String> {
    #[cfg(target_os = "macos")]
    let text = {
        let output = std::process::Command::new("/usr/sbin/sysctl")
            .args([
                "-n",
                "net.inet.ip.portrange.first",
                "net.inet.ip.portrange.last",
            ])
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("cannot read OS ephemeral port range".to_owned());
        }
        String::from_utf8(output.stdout).map_err(|error| error.to_string())?
    };
    #[cfg(target_os = "linux")]
    let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .map_err(|error| error.to_string())?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let text = return Err("headless listener allocation supports Linux and macOS".to_owned());
    parse_range(&text)
}

fn parse_range(text: &str) -> Result<RangeInclusive<u16>, String> {
    let values = text
        .split_whitespace()
        .map(str::parse::<u16>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    match values.as_slice() {
        [first, last] if *first > 0 && first <= last => Ok(*first..=*last),
        _ => Err("invalid OS ephemeral port range".to_owned()),
    }
}

#[test]
fn ephemeral_range_requires_two_ordered_ports() {
    assert_eq!(parse_range("49152\n65535\n"), Ok(49152..=65535));
    assert_eq!(parse_range("32768 60999"), Ok(32768..=60999));
    for invalid in [
        "",
        "0 100",
        "65535 49152",
        "1 2 3",
        "65536 65537",
        "one two",
    ] {
        assert!(parse_range(invalid).is_err());
    }
}

#[test]
fn reservations_survive_another_test_process() -> Result<(), Box<dyn std::error::Error>> {
    const RESERVED: &str = "MESHSPAN_PORT_RESERVATION_PROOF";
    if let Some(value) = std::env::var_os(RESERVED) {
        let port = value
            .to_str()
            .ok_or("invalid reserved port")?
            .parse::<u16>()?;
        // The daemon has not bound yet (or is between restarts): OS probing alone succeeds.
        drop(TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))?);
        NEXT.store(u32::from(port) - FIRST, Ordering::Relaxed);
        assert_ne!(
            tcp()?.port(),
            port,
            "another process reused a reserved TCP port"
        );
        NEXT.store(u32::from(port) - FIRST, Ordering::Relaxed);
        assert_ne!(
            udp()?.port(),
            port,
            "another process reused a reserved UDP port"
        );
        return Ok(());
    }
    let reserved = tcp()?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "ports::reservations_survive_another_test_process",
            "--nocapture",
        ])
        .env(RESERVED, reserved.port().to_string())
        .status()?;
    assert!(child.success(), "cross-process listener reservation failed");
    Ok(())
}
