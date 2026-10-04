// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::baggage::{Baggage, parse_baggage_header};
use crate::config;
use crate::identity::Identity;
use crate::proxy::{BAGGAGE_HEADER, Error};
use crate::tls::revocation::{self, RevocationHandle};
use bytes::{Buf, Bytes};
use h2::SendStream;
use h2::client::{Connection, SendRequest};
use http::Request;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio::sync::watch::{self, Receiver};
use tracing::{Instrument, debug, error, trace, warn};

#[derive(Debug, Clone)]
// H2ConnectClient is a wrapper abstracting h2
pub struct H2ConnectClient {
    sender: SendRequest<Bytes>,
    pub max_allowed_streams: u16,
    stream_count: Arc<AtomicU16>,
    wl_key: WorkloadKey,
    /// Tunnel revocation signal, surfaced to downstream connections via [`Self::revoked_receiver`]
    /// so they can attribute a revoked teardown as `CERT_REVOKED`.
    /// `None` when CRL enforcement is disabled.
    revoked_rx: Option<watch::Receiver<bool>>,
    trust_domain_rx: Option<watch::Receiver<bool>>,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct WorkloadKey {
    pub src_id: Identity,
    pub dst_id: Vec<Identity>,
    // In theory we can just use src,dst,node. However, the dst has a check that
    // the L3 destination IP matches the HBONE IP. This could be loosened to just assert they are the same identity maybe.
    pub dst: SocketAddr,
    // Because we spoof the source IP, we need to key on this as well. Note: for in-pod its already per-pod
    // pools anyways.
    pub src: IpAddr,
}

impl Display for WorkloadKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})->{}[", self.src, &self.src_id, self.dst,)?;
        for i in &self.dst_id {
            write!(f, "{i}")?;
        }
        write!(f, "]")
    }
}

impl H2ConnectClient {
    pub fn is_for_workload(&self, wl_key: &WorkloadKey) -> Result<(), crate::proxy::Error> {
        if !(self.wl_key == *wl_key) {
            Err(crate::proxy::Error::Generic(
                "connection does not match workload key!".into(),
            ))
        } else {
            Ok(())
        }
    }

    // will_be_at_max_streamcount checks if a stream will be maxed out if we send one more request on it
    pub fn will_be_at_max_streamcount(&self) -> bool {
        let future_count = self.stream_count.load(Ordering::Relaxed) + 1;
        trace!(
            "checking streamcount: {future_count} >= {}",
            self.max_allowed_streams
        );
        future_count >= self.max_allowed_streams
    }

    pub fn ready_to_use(&mut self) -> bool {
        if self.trust_domain_rx.as_ref().is_some_and(|r| *r.borrow()) {
            return false;
        }
        let cx = &mut Context::from_waker(futures::task::noop_waker_ref());
        match self.sender.poll_ready(cx) {
            Poll::Ready(Ok(_)) => true,
            // We may have gotten GoAway, etc
            Poll::Ready(Err(_)) => false,
            Poll::Pending => {
                // Given our current usage, I am not sure this can ever be the case.
                // If it is, though, err on the safe side and do not use the connection
                warn!("checked out connection is Pending, skipping");
                false
            }
        }
    }

    pub async fn send_request(
        &mut self,
        req: http::Request<()>,
    ) -> Result<(crate::proxy::h2::H2Stream, Option<Baggage>), Error> {
        if self.trust_domain_rx.as_ref().is_some_and(|r| *r.borrow()) {
            return Err(Error::TrustDomainRemoved);
        }
        let cur = self.stream_count.fetch_add(1, Ordering::SeqCst);
        trace!(current_streams = cur, "sending request");
        let (send, recv, baggage) = match self.internal_send(req).await {
            Ok(r) => r,
            Err(e) => {
                // Request failed, so drop the stream now
                self.stream_count.fetch_sub(1, Ordering::SeqCst);
                return Err(e);
            }
        };

        let (dropped1, dropped2) = crate::proxy::h2::DropCounter::new(self.stream_count.clone());
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: dropped1,
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: dropped2,
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok((h2, baggage))
    }

    // helper to allow us to handle errors once
    async fn internal_send(
        &mut self,
        req: Request<()>,
    ) -> Result<(SendStream<Bytes>, h2::RecvStream, Option<Baggage>), Error> {
        // "This function must return `Ready` before `send_request` is called"
        // We should always be ready though, because we make sure we don't go over the max stream limit out of band.
        futures::future::poll_fn(|cx| self.sender.poll_ready(cx)).await?;
        let (response, stream) = self.sender.send_request(req, false)?;
        let response = response.await?;
        if response.status() != 200 {
            return Err(Error::HttpStatus(response.status()));
        }
        let baggage = parse_baggage_header(response.headers().get_all(BAGGAGE_HEADER)).ok();
        Ok((stream, response.into_body(), baggage))
    }

    /// A receiver for this tunnel's CRL revocation signal, or `None` when CRL enforcement is disabled
    pub fn revoked_receiver(&self) -> Option<watch::Receiver<bool>> {
        self.revoked_rx.clone()
    }
}

pub async fn spawn_connection(
    cfg: Arc<config::Config>,
    s: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    driver_drain: Receiver<bool>,
    wl_key: WorkloadKey,
    revocation: Option<RevocationHandle>,
    trust_domain: Option<crate::tls::trust_domains::TrustDomainHandle>,
) -> Result<H2ConnectClient, Error> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        .initial_max_send_streams(cfg.pool_max_streams_per_conn as usize)
        .max_header_list_size(1024 * 16)
        // 4mb. Aligned with window_size such that we can fill up the buffer, then flush it all in one go, without buffering up too much.
        .max_send_buffer_size(cfg.window_size as usize)
        .enable_push(false);

    let (send_req, connection) = builder
        .handshake::<_, Bytes>(s)
        .await
        .map_err(Error::Http2Handshake)?;

    // We store max as u16, so if they report above that max size we just cap at u16::MAX
    let max_allowed_streams = std::cmp::min(
        cfg.pool_max_streams_per_conn,
        connection
            .max_concurrent_send_streams()
            .try_into()
            .unwrap_or(u16::MAX),
    );
    // Subscribe to the tunnel's revocation signal (if CRL enforcement is on) before the revocation
    // state is moved into the driver task, so each stream this connection produces can attribute a
    // revoked teardown.
    let revoked_rx = revocation.as_ref().map(|r| r.subscribe_revoked());
    let trust_domain_rx = trust_domain.as_ref().map(|h| h.subscribe());
    // spawn a task to poll the connection and drive the HTTP state
    // if we got a drain for that connection, respect it in a race
    // it is important to have a drain here, or this connection will never terminate
    tokio::spawn(
        async move {
            drive_connection(connection, driver_drain, revocation, trust_domain).await;
        }
        .in_current_span(),
    );

    let c = H2ConnectClient {
        sender: send_req,
        stream_count: Arc::new(AtomicU16::new(0)),
        max_allowed_streams,
        wl_key,
        revoked_rx,
        trust_domain_rx,
    };
    Ok(c)
}

async fn drive_connection<S, B>(
    mut conn: Connection<S, B>,
    mut driver_drain: Receiver<bool>,
    mut revocation: Option<RevocationHandle>,
    mut trust_domain: Option<crate::tls::trust_domains::TrustDomainHandle>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    B: Buf,
{
    let ping_pong = conn
        .ping_pong()
        .expect("ping_pong should only be called once");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(
        super::do_ping_pong(ping_pong, ping_drop_tx, dropped.clone()).in_current_span(),
    );

    tokio::select! {
        _ = driver_drain.changed() => {
            debug!("draining outer HBONE connection");
        }
        _ = ping_drop_rx => {
            warn!("HBONE ping timeout/error");
        }
        // CRL update revoked a cert in this connection's upstream chain. Revocation is a security
        // event, so we tear the tunnel down abruptly (let `conn` drop below) so any in-flight
        // streams multiplexed over it are reset. `revoked()` fires this tunnel's revocation signal
        // before returning (and thus before the drop), so each downstream connection attributes
        // `CERT_REVOKED` rather than a generic reset.
        _ = revocation::wait_for_revocation(revocation.as_mut()) => {
            if let Some(rev) = revocation.as_ref() {
                debug!(
                    peer = %rev.peer(),
                    "terminating outbound connection: upstream certificate revoked by CRL update"
                );
            }
        }
        _ = crate::tls::trust_domains::wait_for_removal(trust_domain.as_mut()) => {
            debug!("terminating outbound connection: selected SPIFFE bundle removed");
        }
        res = conn => {
            match res {
                Err(e) => {
                    error!("Error in HBONE connection handshake: {:?}", e);
                }
                Ok(_) => {
                    debug!("done with HBONE connection handshake: {:?}", res);
                }
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod bundle_tests {
    use super::*;
    use crate::tls::mock::{bundle_map, generate_ca_material, generate_workload};
    use crate::tls::trust_domains::TrustDomainManager;
    use std::io::{Seek, SeekFrom, Write};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn selected_bundle_removal_closes_active_native_h2_in_both_directions() {
        for removed_domain in ["client", "server"] {
            let ca = generate_ca_material("root", 1);
            let pem = ca.1.self_signed(&ca.0).unwrap().pem();
            let mut file = tempfile::NamedTempFile::new().unwrap();
            let initial = bundle_map(&[
                ("client", vec![pem.as_bytes()]),
                ("server", vec![pem.as_bytes()]),
            ]);
            file.write_all(&initial).unwrap();
            let manager = TrustDomainManager::new(file.path().to_path_buf());
            let server = generate_workload(&ca, "spiffe://server/ns/n/sa/server");
            let client = generate_workload(&ca, "spiffe://client/ns/n/sa/client");
            let server_id = server.identity().unwrap();
            let client_id = client.identity().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tcp_client, tcp_server) =
                tokio::join!(TcpStream::connect(addr), listener.accept());
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
                server.server_config(Some(&manager), None).unwrap(),
            ));
            let accept =
                tokio::spawn(async move { acceptor.accept(tcp_server.unwrap().0).await.unwrap() });
            let client_tls = client
                .outbound_connector_with_trust_domains(
                    vec![server_id.clone()],
                    None,
                    Some(&manager),
                )
                .unwrap()
                .connect(tcp_client.unwrap())
                .await
                .unwrap();
            let server_tls = accept.await.unwrap();
            let server_handle = server
                .register_peer(
                    Some(&manager),
                    server_tls.get_ref().1,
                    client_id.clone(),
                    webpki::KeyUsage::client_auth(),
                )
                .unwrap();
            let client_handle = client
                .register_peer(
                    Some(&manager),
                    client_tls.get_ref().1,
                    server_id.clone(),
                    webpki::KeyUsage::server_auth(),
                )
                .unwrap();
            let cfg = Arc::new(crate::test_helpers::test_config());
            let (_drain_trigger, drain) = crate::drain::new();
            let (_force_tx, force_rx) = watch::channel(());
            let server_cfg = cfg.clone();
            let serving = tokio::spawn(async move {
                super::super::server::serve_connection(
                    server_cfg,
                    server_tls,
                    drain,
                    force_rx,
                    None,
                    Some(server_handle),
                    |req| async move {
                        let stream = req.send_response(http::Response::new(())).await.unwrap();
                        let mut stream = super::super::TokioH2Stream::new(stream);
                        let _ = stream.write_all(b"x").await;
                        let mut byte = [0];
                        let _ = stream.read(&mut byte).await;
                    },
                )
                .await
            });
            let (_driver_tx, driver_rx) = watch::channel(false);
            let key = WorkloadKey {
                src_id: client_id,
                dst_id: vec![server_id],
                src: addr.ip(),
                dst: addr,
            };
            let mut sender =
                spawn_connection(cfg, client_tls, driver_rx, key, None, Some(client_handle))
                    .await
                    .unwrap();
            let request = || {
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri(addr.to_string())
                    .body(())
                    .unwrap()
            };
            let (stream, _) = sender.send_request(request()).await.unwrap();
            let mut stream = super::super::TokioH2Stream::new(stream);
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [b'x']);
            // A new generation retaining this selected anchor must preserve an existing tunnel.
            file.as_file_mut().set_len(0).unwrap();
            file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&initial).unwrap();
            manager.reload().unwrap();
            assert!(sender.ready_to_use());
            let (second, _) = sender.send_request(request()).await.unwrap();
            let mut second = super::super::TokioH2Stream::new(second);
            second.read_exact(&mut byte).await.unwrap();
            let retained = if removed_domain == "client" {
                "server"
            } else {
                "client"
            };
            file.as_file_mut().set_len(0).unwrap();
            file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&bundle_map(&[(retained, vec![pem.as_bytes()])]))
                .unwrap();
            manager.reload().unwrap();
            if removed_domain == "server" {
                assert!(!sender.ready_to_use());
                assert!(matches!(
                    sender.send_request(request()).await,
                    Err(Error::TrustDomainRemoved)
                ));
            }
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .expect("active stream must be reset");
            assert!(
                read.is_err() || read.unwrap() == 0,
                "removed peer continued serving"
            );
            tokio::time::timeout(Duration::from_secs(2), serving)
                .await
                .expect("native server driver must exit")
                .unwrap()
                .unwrap();
        }
    }
}
