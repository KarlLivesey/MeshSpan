// SPDX-License-Identifier: GPL-2.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::{SmbConnectionHandler, SmbHandlerFuture, SmbServer, SmbServerLimits};

#[tokio::test]
async fn real_direct_tcp_listener_isolates_bad_connections_and_frames_responses()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = SmbServerLimits::new(1_024, Duration::from_secs(2))?;
    let server =
        SmbServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), limits).await?;
    let address = server.local_addr()?;
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(
        server.run_until(|| Ok::<_, Infallible>(EchoHandler), async move {
            drop(stopped.await);
        }),
    );

    let mut hostile = TcpStream::connect(address).await?;
    hostile.write_all(&[1, 0, 0, 64]).await?;
    hostile.write_all(&[0; 64]).await?;
    drop(hostile);

    let mut client = TcpStream::connect(address).await?;
    let mut request = vec![0; 64];
    request[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    client.write_all(&[0, 0, 0, 64]).await?;
    client.write_all(&request).await?;
    let mut response_header = [0; 4];
    timeout(
        Duration::from_secs(2),
        client.read_exact(&mut response_header),
    )
    .await??;
    assert_eq!(response_header, [0, 0, 0, 64]);
    let mut response = vec![0; 64];
    timeout(Duration::from_secs(2), client.read_exact(&mut response)).await??;
    assert_eq!(&response[..4], &[0xfe, b'S', b'M', b'B']);
    assert_eq!(response[63], 1);

    drop(client);
    let _ = stop.send(());
    timeout(Duration::from_secs(2), task).await???;
    Ok(())
}

struct EchoHandler;

impl SmbConnectionHandler for EchoHandler {
    type Error = Infallible;

    fn handle(&mut self, mut request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error> {
        Box::pin(async move {
            if let Some(last) = request.last_mut() {
                *last = 1;
            }
            Ok(Some(request))
        })
    }
}
