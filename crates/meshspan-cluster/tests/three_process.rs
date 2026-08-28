// SPDX-License-Identifier: GPL-2.0-only

//! Real-process Stage 3 acceptance proof over Quinn/mTLS and durable SQLite state.

use std::error::Error;
use std::fs;
use std::net::{SocketAddr, TcpListener as StandardTcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CERTIFICATE_NAME: &str = "meshspan.internal";
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_process_cluster_survives_lost_reply_and_leader_restart() -> Result<(), Box<dyn Error>>
{
    let temporary = TempDir::new()?;
    let launches = build_launches(temporary.path())?;
    let mut cluster = ProcessCluster::start(&launches)?;

    for launch in &launches {
        wait_for_response(launch.control_address, "INFO", None).await?;
    }
    assert_eq!(
        command(launches[0].control_address, "ELECT").await?,
        "ELECTION_STARTED"
    );
    wait_for_response(launches[0].control_address, "INFO", Some("LEADER")).await?;
    wait_for_response(
        launches[1].control_address,
        "INFO",
        Some("FOLLOWER_WITH_LEADER"),
    )
    .await?;

    assert_eq!(
        command(launches[1].control_address, "PROPOSE 21").await?,
        "REDIRECT 1"
    );
    assert_eq!(
        command(launches[0].control_address, "PROPOSE 21").await?,
        "ACCEPTED"
    );
    wait_for_response(launches[2].control_address, "STATUS 21", Some("COMMITTED")).await?;

    abandon_response(launches[0].control_address, "PROPOSE 22").await?;
    wait_for_response(launches[1].control_address, "STATUS 22", Some("COMMITTED")).await?;

    cluster.stop(1)?;
    assert_eq!(
        command(launches[1].control_address, "ELECT").await?,
        "ELECTION_STARTED"
    );
    wait_for_response(launches[1].control_address, "INFO", Some("LEADER")).await?;
    wait_for_response(
        launches[2].control_address,
        "INFO",
        Some("FOLLOWER_WITH_LEADER"),
    )
    .await?;
    assert_eq!(
        command(launches[2].control_address, "PROPOSE 23").await?,
        "REDIRECT 2"
    );
    assert_eq!(
        command(launches[1].control_address, "PROPOSE 23").await?,
        "ACCEPTED"
    );
    wait_for_response(launches[2].control_address, "STATUS 23", Some("COMMITTED")).await?;

    cluster.restart(&launches[0])?;
    wait_for_response(launches[0].control_address, "INFO", None).await?;
    wait_for_response(launches[0].control_address, "STATUS 23", Some("COMMITTED")).await?;
    Ok(())
}

struct NodeLaunch {
    number: u8,
    quic_address: SocketAddr,
    control_address: SocketAddr,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    authority_path: PathBuf,
    state_path: PathBuf,
    log_path: PathBuf,
}

struct RunningNode {
    number: u8,
    child: Child,
}

struct ProcessCluster {
    nodes: Vec<RunningNode>,
}

impl ProcessCluster {
    fn start(launches: &[NodeLaunch]) -> Result<Self, Box<dyn Error>> {
        let nodes = launches
            .iter()
            .map(spawn_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { nodes })
    }

    fn stop(&mut self, number: u8) -> Result<(), Box<dyn Error>> {
        let index = self
            .nodes
            .iter()
            .position(|node| node.number == number)
            .ok_or("running node was not found")?;
        let mut node = self.nodes.swap_remove(index);
        node.child.kill()?;
        node.child.wait()?;
        Ok(())
    }

    fn restart(&mut self, launch: &NodeLaunch) -> Result<(), Box<dyn Error>> {
        self.nodes.push(spawn_node(launch)?);
        Ok(())
    }
}

impl Drop for ProcessCluster {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            let _kill_result = node.child.kill();
            let _wait_result = node.child.wait();
        }
    }
}

fn spawn_node(launch: &NodeLaunch) -> Result<RunningNode, Box<dyn Error>> {
    let log = fs::File::create(&launch.log_path)?;
    let error_log = log.try_clone()?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_meshspan-stage3-node"));
    command
        .args(["--node", &launch.number.to_string()])
        .args(["--listen", &launch.quic_address.to_string()])
        .args(["--control", &launch.control_address.to_string()])
        .args(["--certificate", path_text(&launch.certificate_path)?])
        .args(["--private-key", path_text(&launch.private_key_path)?])
        .args(["--authority", path_text(&launch.authority_path)?])
        .args(["--state", path_text(&launch.state_path)?]);
    for peer in launch_peers(launch)? {
        command.args(["--peer", &peer]);
    }
    let child = command
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .spawn()?;
    Ok(RunningNode {
        number: launch.number,
        child,
    })
}

fn launch_peers(launch: &NodeLaunch) -> Result<Vec<String>, Box<dyn Error>> {
    let directory = launch
        .certificate_path
        .parent()
        .ok_or("certificate path has no parent")?;
    let addresses = read_addresses(directory)?;
    (1_u8..=3)
        .filter(|number| *number != launch.number)
        .map(|number| {
            let address = addresses[usize::from(number - 1)];
            let certificate = directory.join(format!("node-{number}.der"));
            Ok(format!("{number},{address},{}", path_text(&certificate)?))
        })
        .collect()
}

fn build_launches(directory: &Path) -> Result<Vec<NodeLaunch>, Box<dyn Error>> {
    let quic_addresses = unique_addresses(3, reserve_udp_address)?;
    let control_addresses = unique_addresses(3, reserve_tcp_address)?;
    write_addresses(directory, &quic_addresses)?;
    let authority_path = directory.join("authority.der");
    let leaves = write_certificates(directory, &authority_path)?;
    Ok((1_u8..=3)
        .map(|number| {
            let index = usize::from(number - 1);
            NodeLaunch {
                number,
                quic_address: quic_addresses[index],
                control_address: control_addresses[index],
                certificate_path: leaves[index].0.clone(),
                private_key_path: leaves[index].1.clone(),
                authority_path: authority_path.clone(),
                state_path: directory.join(format!("node-{number}.sqlite")),
                log_path: directory.join(format!("node-{number}.log")),
            }
        })
        .collect())
}

fn write_certificates(
    directory: &Path,
    authority_path: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, Box<dyn Error>> {
    let mut authority_parameters = CertificateParams::new(Vec::<String>::new())?;
    authority_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_parameters
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    let authority_key = KeyPair::generate()?;
    let authority_certificate = authority_parameters.self_signed(&authority_key)?;
    fs::write(authority_path, authority_certificate.der())?;
    let issuer = Issuer::new(authority_parameters, authority_key);
    (1_u8..=3)
        .map(|number| write_leaf(directory, number, &issuer))
        .collect()
}

fn write_leaf(
    directory: &Path,
    number: u8,
    issuer: &Issuer<'_, KeyPair>,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(vec![CERTIFICATE_NAME.to_owned()])?;
    parameters
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    parameters.extended_key_usages.extend([
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]);
    let key = KeyPair::generate()?;
    let certificate: Certificate = parameters.signed_by(&key, issuer)?;
    let certificate_path = directory.join(format!("node-{number}.der"));
    let private_key_path = directory.join(format!("node-{number}.key"));
    fs::write(&certificate_path, certificate.der())?;
    fs::write(&private_key_path, key.serialize_der())?;
    Ok((certificate_path, private_key_path))
}

async fn wait_for_response(
    address: SocketAddr,
    request: &str,
    expected: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let started = Instant::now();
    loop {
        if let Ok(response) = command(address, request).await
            && expected.is_none_or(|value| response == value)
        {
            return Ok(response);
        }
        if started.elapsed() >= WAIT_LIMIT {
            return Err(format!("timed out waiting for {request} at {address}").into());
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

async fn command(address: SocketAddr, request: &str) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    let mut response = [0_u8; MAXIMUM_RESPONSE_BYTES];
    let length = stream.read(&mut response).await?;
    Ok(std::str::from_utf8(&response[..length])?.trim().to_owned())
}

async fn abandon_response(address: SocketAddr, request: &str) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    drop(stream);
    Ok(())
}

const MAXIMUM_RESPONSE_BYTES: usize = 128;

fn unique_addresses(
    count: usize,
    reserve: fn() -> Result<SocketAddr, Box<dyn Error>>,
) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    let mut addresses = Vec::with_capacity(count);
    while addresses.len() < count {
        let address = reserve()?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

fn reserve_udp_address() -> Result<SocketAddr, Box<dyn Error>> {
    Ok(UdpSocket::bind("127.0.0.1:0")?.local_addr()?)
}

fn reserve_tcp_address() -> Result<SocketAddr, Box<dyn Error>> {
    Ok(StandardTcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

fn write_addresses(directory: &Path, addresses: &[SocketAddr]) -> Result<(), Box<dyn Error>> {
    let contents = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(directory.join("addresses"), contents)?;
    Ok(())
}

fn read_addresses(directory: &Path) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    fs::read_to_string(directory.join("addresses"))?
        .lines()
        .map(|line| line.parse().map_err(Into::into))
        .collect()
}

fn path_text(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| "path is not valid UTF-8".into())
}
