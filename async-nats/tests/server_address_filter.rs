// Copyright 2020-2022 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use async_nats::rustls;
use async_nats::{ConnectErrorKind, ConnectOptions};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

async fn serve(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.unwrap();
    socket.write_all(b"INFO {}\r\n").await.unwrap();
    let mut socket = BufReader::new(socket);
    let mut line = String::new();
    while socket.read_line(&mut line).await.unwrap_or(0) > 0 {
        if line == "PING\r\n" {
            socket.get_mut().write_all(b"PONG\r\n").await.unwrap();
        }
        line.clear();
    }
}

fn options() -> ConnectOptions {
    ConnectOptions::new()
        .connection_timeout(Duration::from_secs(2))
        .reconnect_delay_callback(|_| Duration::from_millis(10))
}

#[tokio::test]
async fn absent_filter_keeps_nats_allowed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(listener));
    options().connect(format!("nats://{addr}")).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn configured_filter_allows_nats_and_rechecks_reconnect() {
    let blocked = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocked.local_addr().unwrap();
    let healthy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let healthy_addr = healthy.local_addr().unwrap();
    let server = tokio::spawn(serve(healthy));
    let calls = Arc::new(AtomicUsize::new(0));
    let changed = Arc::new(AtomicBool::new(false));
    let observed = calls.clone();
    let deny = changed.clone();
    let client = options()
        .retain_servers_order()
        .server_address_filter(move |_, addr| {
            observed.fetch_add(1, Ordering::SeqCst);
            addr != blocked_addr && !deny.load(Ordering::SeqCst)
        })
        .connect(vec![
            format!("nats://{blocked_addr}"),
            format!("nats://{healthy_addr}"),
        ])
        .await
        .unwrap();
    let first = calls.load(Ordering::SeqCst);
    assert!(first >= 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), blocked.accept())
            .await
            .is_err()
    );
    changed.store(true, Ordering::SeqCst);
    server.abort();
    tokio::time::timeout(Duration::from_secs(3), async {
        while calls.load(Ordering::SeqCst) == first {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), blocked.accept())
            .await
            .is_err()
    );
    drop(client);
}

#[tokio::test]
async fn any_blocked_answer_rejects_whole_seed_before_dial() {
    let v4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port))
        .await
        .unwrap();
    let addresses = tokio::net::lookup_host(("localhost", port))
        .await
        .unwrap()
        .collect::<Vec<_>>();
    assert!(addresses.iter().any(|a| a.is_ipv4()) && addresses.iter().any(|a| a.is_ipv6()));
    let error = options()
        .server_address_filter(|_, addr| addr.is_ipv4())
        .connect(format!("nats://localhost:{port}"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ConnectErrorKind::Io);
    assert!(tokio::time::timeout(Duration::from_millis(20), v4.accept())
        .await
        .is_err());
    assert!(tokio::time::timeout(Duration::from_millis(20), v6.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn websocket_schemes_are_rejected_before_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    for scheme in ["ws", "wss"] {
        let error = options()
            .server_address_filter(|_, _| true)
            .connect(format!("{scheme}://127.0.0.1:{port}"))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), ConnectErrorKind::Io, "{scheme}");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn configured_filter_preserves_tls_and_original_sni() {
    let certificates =
        CertificateDer::pem_slice_iter(include_bytes!("configs/certs/server-cert.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("configs/certs/server-key.pem")).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket
            .write_all(b"INFO {\"tls_required\":true}\r\n")
            .await
            .unwrap();
        let socket = acceptor.accept(socket).await.unwrap();
        assert_eq!(socket.get_ref().1.server_name(), Some("localhost"));
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        while socket.read_line(&mut line).await.unwrap_or(0) > 0 {
            if line == "PING\r\n" {
                socket.get_mut().write_all(b"PONG\r\n").await.unwrap();
                return;
            }
            line.clear();
        }
    });
    let options = options()
        .add_root_certificates(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/configs/certs/rootCA.pem"
            )
            .into(),
        )
        .server_address_filter(|server, addr| {
            assert_eq!(server.host(), "localhost");
            addr.ip().is_loopback()
        });
    options
        .connect(format!("tls://localhost:{port}"))
        .await
        .unwrap();
    server.await.unwrap();
}
