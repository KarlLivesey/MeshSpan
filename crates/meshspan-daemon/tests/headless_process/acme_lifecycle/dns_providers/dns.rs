// SPDX-License-Identifier: GPL-2.0-only

//! Independent NS/TXT wire fixture; keeps unrelated TXT data through publication and cleanup.

use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle};

use super::{Failure, SharedRecords, UNRELATED_TXT};

pub(super) struct Server {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), Failure>>,
}

impl Server {
    pub async fn start(records: SharedRecords) -> Result<Self, Failure> {
        let socket = UdpSocket::bind("127.0.0.1:53").await?;
        let (shutdown, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            loop {
                tokio::select! {
                    _ = &mut stopped => return Ok(()),
                    received = socket.recv_from(&mut buffer) => {
                        let (length, peer) = received?;
                        let response = respond(&buffer[..length], &records)?;
                        socket.send_to(&response, peer).await?;
                    }
                }
            }
        });
        Ok(Self { shutdown, task })
    }

    pub async fn stop(self) -> Result<(), Failure> {
        // A stopped receiver means the task has already failed; its result below retains that error.
        let signal = self.shutdown.send(());
        self.task.await??;
        signal.map_err(|()| "DNS fixture stopped before shutdown")?;
        Ok(())
    }
}

fn respond(request: &[u8], records: &SharedRecords) -> Result<Vec<u8>, Failure> {
    if request.len() < 17 || request.get(4..12) != Some(&[0, 1, 0, 0, 0, 0, 0, 0]) {
        return Err("expected one uncompressed DNS question".into());
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*request.get(offset).ok_or("missing DNS label")?);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return Err("compressed or oversized DNS label".into());
        }
        labels.push(std::str::from_utf8(
            request
                .get(offset..offset + length)
                .ok_or("short DNS label")?,
        )?);
        offset += length;
    }
    let question = request.get(offset..).ok_or("missing DNS type")?;
    if question.len() != 4 || question[2..] != [0, 1] {
        return Err("unexpected DNS class or trailing bytes".into());
    }
    let name = labels.join(".");
    if name != "_acme-challenge.meshspan.local" {
        return Err(format!("unexpected DNS owner {name}").into());
    }
    let kind = u16::from_be_bytes([question[0], question[1]]);
    let answers = answer_data(kind, records)?;
    let mut response = Vec::new();
    response.extend_from_slice(&request[..2]);
    response.extend_from_slice(&0x8400_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&u16::try_from(answers.len())?.to_be_bytes());
    response.extend_from_slice(&[0; 4]);
    response.extend_from_slice(&request[12..]);
    for answer in answers {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&kind.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&u16::try_from(answer.len())?.to_be_bytes());
        response.extend_from_slice(&answer);
    }
    Ok(response)
}

fn answer_data(kind: u16, records: &SharedRecords) -> Result<Vec<Vec<u8>>, Failure> {
    let mut state = records.lock().map_err(|_| "DNS records poisoned")?;
    match kind {
        2 => {
            state.discovery_queries += 1;
            Ok(vec![b"\x02ns\x08meshspan\x04test\x00".to_vec()])
        }
        16 => {
            let mut answers = vec![txt(UNRELATED_TXT)?];
            if let Some(record) = &state.managed {
                answers.push(txt(&record.value)?);
                state.positive_probes += 1;
            }
            Ok(answers)
        }
        _ => Err("unexpected DNS question type".into()),
    }
}

fn txt(value: &str) -> Result<Vec<u8>, Failure> {
    let mut answer = vec![u8::try_from(value.len())?];
    answer.extend_from_slice(value.as_bytes());
    Ok(answer)
}
