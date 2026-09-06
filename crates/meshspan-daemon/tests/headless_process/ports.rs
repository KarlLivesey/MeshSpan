// SPDX-License-Identifier: GPL-2.0-only

//! Listener candidates stay outside the OS client-port pool during child startup.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

const FIRST: u32 = 16_384;
const COUNT: u32 = 16_384;
static NEXT: AtomicU32 = AtomicU32::new(0);
static EPHEMERAL: OnceLock<Result<RangeInclusive<u16>, String>> = OnceLock::new();

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
        match bind(SocketAddr::from(([127, 0, 0, 1], port))) {
            Ok(address) => return Ok(address),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no test listener port outside the OS ephemeral range",
    ))
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
