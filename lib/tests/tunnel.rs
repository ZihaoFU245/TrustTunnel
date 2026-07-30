use bytes::{BufMut, BytesMut};
use futures::{future, FutureExt, StreamExt};
use http::Request;
use log::info;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use trusttunnel::net_utils;

#[allow(dead_code)]
mod common;

const TCP_CONTENT_SIZE: usize = 2 * 1024 * 1024;
const UDP_CHUNK_SIZE: usize = 1024;
const UDP_CONTENT_SIZE: usize = 8 * UDP_CHUNK_SIZE;
const MANGLED_UDP_HEADER_LENGTH: usize = 4 + 2 * (16 + 2);
const EXPECTED_MANGLED_UDP_LENGTH: usize =
    UDP_CONTENT_SIZE + (UDP_CONTENT_SIZE / UDP_CHUNK_SIZE) * MANGLED_UDP_HEADER_LENGTH;
const PADDING_HEADER_VALUE: &str = "!#$()+<>?@[]^`{}~~~~~~~~~~~~~~";
const PADDING_HEADER_RANDOM_CHARACTERS: &[u8; 16] = b"!#$()+<>?@[]^`{}";
const PADDING_HEADER_RANDOM_PREFIX_SIZE: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PaddingState {
    Disabled,
    Enabled,
    Ignored,
}

impl PaddingState {
    fn requested(self) -> bool {
        self != Self::Disabled
    }

    fn expected_in_response(self) -> bool {
        self == Self::Enabled
    }
}

macro_rules! tcp_download_tests {
    ($($name:ident: $make_tunnel_fn:expr, $padding:expr;)*) => {
    $(
        #[tokio::test]
        async fn $name() {
            common::set_up_logger();
            let endpoint_address = common::make_endpoint_address();

            let client_task = async {
                let server_address = run_tcp_server(true);
                tokio::time::sleep(Duration::from_secs(1)).await;

                let padding = $padding;
                let (conn_driver, io) = $make_tunnel_fn(
                    endpoint_address,
                    server_address.to_string(),
                    padding,
                ).await;

                let exchange = async {
                    let mut io = io.await;
                    if padding == PaddingState::Enabled {
                        read_padded_download(&mut io).await;
                    } else {
                        read_unpadded_download(&mut io).await;
                    }
                };

                futures::pin_mut!(exchange);
                match future::select(conn_driver, exchange).await {
                    future::Either::Left((r, exchange)) => {
                        info!("HTTP connection closed with result: {:?}", r);
                        exchange.await
                    }
                    future::Either::Right(_) => (),
                }
            };

            tokio::select! {
                _ = common::run_endpoint(&endpoint_address) => unreachable!(),
                _ = client_task => (),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
            }
        }
    )*
    }
}

macro_rules! tcp_upload_tests {
    ($($name:ident: $make_tunnel_fn:expr, $padding:expr;)*) => {
    $(
        #[tokio::test]
        async fn $name() {
            common::set_up_logger();
            let endpoint_address = common::make_endpoint_address();

            let client_task = async {
                let server_address = run_tcp_server(false);
                tokio::time::sleep(Duration::from_secs(1)).await;

                let padding = $padding;
                let (conn_driver, io) = $make_tunnel_fn(
                    endpoint_address,
                    server_address.to_string(),
                    padding,
                ).await;

                let exchange = async {
                    let mut io = io.await;
                    if padding == PaddingState::Enabled {
                        write_padded_upload(&mut io).await;
                    } else {
                        let mut content = common::make_stream_of_chunks(TCP_CONTENT_SIZE, None);
                        while let Some(chunk) = content.next().await {
                            io.write_all(chunk).await.unwrap();
                        }
                    }
                    io.flush().await.unwrap();

                    if padding == PaddingState::Enabled {
                        assert_eq!(read_padded_frame(&mut io).await, [1]);
                    } else {
                        let mut ack = [0; 1];
                        io.read_exact(&mut ack).await.unwrap();
                    }
                    let mut trailing = Vec::new();
                    io.read_to_end(&mut trailing).await.unwrap();
                    assert!(trailing.is_empty());
                };

                futures::pin_mut!(exchange);
                match future::select(conn_driver, exchange).await {
                    future::Either::Left((r, exchange)) => {
                        info!("HTTP connection closed with result: {:?}", r);
                        exchange.await
                    }
                    future::Either::Right(_) => (),
                }
            };

            tokio::select! {
                _ = common::run_endpoint(&endpoint_address) => unreachable!(),
                _ = client_task => (),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
            }
        }
    )*
    }
}

tcp_download_tests! {
    h1_tcp_download: make_h1_tunnel, PaddingState::Disabled;
    h2_tcp_download: make_h2_tunnel, PaddingState::Disabled;
    h1_padded_tcp_download: make_h1_tunnel, PaddingState::Enabled;
    h2_padded_tcp_download: make_h2_tunnel, PaddingState::Enabled;
}

tcp_upload_tests! {
    h1_tcp_upload: make_h1_tunnel, PaddingState::Disabled;
    h2_tcp_upload: make_h2_tunnel, PaddingState::Disabled;
    h1_padded_tcp_upload: make_h1_tunnel, PaddingState::Enabled;
    h2_padded_tcp_upload: make_h2_tunnel, PaddingState::Enabled;
}

#[tokio::test]
async fn h2_udp_download() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_udp_server(true);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let (conn_driver, io) =
            make_h2_tunnel(endpoint_address, "_udp2".to_string(), PaddingState::Ignored).await;

        let exchange = async {
            let mut io = io.await;
            let hole_puncher = encode_udp_chunk(&server_address, &[1]);
            io.write_all(&hole_puncher).await.unwrap();

            let mut total = 0;
            let mut buf = [0; 64 * 1024];
            while total < EXPECTED_MANGLED_UDP_LENGTH {
                match io.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => total += n,
                }
            }
            assert_eq!(total, EXPECTED_MANGLED_UDP_LENGTH);
        };

        futures::pin_mut!(exchange);
        match future::select(conn_driver, exchange).await {
            future::Either::Left((r, exchange)) => {
                info!("HTTP connection closed with result: {:?}", r);
                exchange.await
            }
            future::Either::Right(_) => (),
        }
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h2_udp_upload() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_udp_server(false);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let (conn_driver, io) = make_h2_tunnel(
            endpoint_address,
            "_udp2".to_string(),
            PaddingState::Disabled,
        )
        .await;

        let exchange = async {
            let mut io = io.await;

            let mut content = common::make_stream_of_chunks(UDP_CONTENT_SIZE, Some(UDP_CHUNK_SIZE))
                .map(|x| encode_udp_chunk(&server_address, x));
            while let Some(chunk) = content.next().await {
                io.write_all(&chunk).await.unwrap();
            }

            let mut ack = [0; UDP_CHUNK_SIZE];
            assert_eq!(
                io.read(&mut ack).await.unwrap(),
                MANGLED_UDP_HEADER_LENGTH + 1
            );
        };

        futures::pin_mut!(exchange);
        match future::select(conn_driver, exchange).await {
            future::Either::Left((r, exchange)) => {
                info!("HTTP connection closed with result: {:?}", r);
                exchange.await
            }
            future::Either::Right(_) => (),
        }
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h3_tcp_download() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_tcp_server(true);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut conn =
            common::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None).await;

        let (response, _) = conn
            .exchange(
                Request::connect(server_address.to_string())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status, http::StatusCode::OK);
        assert_response_padding(&response.headers, PaddingState::Disabled);

        let mut total = 0;
        let mut buf = [0; 64 * 1024];
        while total < TCP_CONTENT_SIZE {
            match conn.recv(&mut buf).await {
                0 => break,
                n => {
                    assert!(buf[..n].iter().all(|byte| *byte == 0));
                    total += n;
                }
            }
        }
        assert_eq!(total, TCP_CONTENT_SIZE);
        assert_eq!(conn.recv(&mut [0]).await, 0);
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h3_padded_tcp_download() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_tcp_server(true);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut conn =
            common::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None).await;

        let (response, _) = conn
            .exchange(
                Request::connect(server_address.to_string())
                    .header("padding", PADDING_HEADER_VALUE)
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status, http::StatusCode::OK);
        assert_response_padding(&response.headers, PaddingState::Enabled);

        read_h3_padded_download(&mut conn).await;
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h3_tcp_upload() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_tcp_server(false);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut conn =
            common::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None).await;

        let (response, _) = conn
            .exchange(
                Request::connect(server_address.to_string())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status, http::StatusCode::OK);
        assert_response_padding(&response.headers, PaddingState::Disabled);

        conn.send(common::make_stream_of_chunks(TCP_CONTENT_SIZE, None))
            .await;
        let mut ack = [0; 1];
        assert_eq!(conn.recv(&mut ack).await, 1);
        assert_eq!(ack, [1]);
        assert_eq!(conn.recv(&mut [0]).await, 0);
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h3_padded_tcp_upload() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_tcp_server(false);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut conn =
            common::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None).await;

        let (response, _) = conn
            .exchange(
                Request::connect(server_address.to_string())
                    .header("padding", PADDING_HEADER_VALUE)
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status, http::StatusCode::OK);
        assert_response_padding(&response.headers, PaddingState::Enabled);

        conn.send(futures::stream::iter(make_padded_upload_chunks()))
            .await;
        assert_eq!(read_h3_padded_frame(&mut conn).await, [1]);
        assert_eq!(conn.recv(&mut [0]).await, 0);
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h3_udp_download() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_udp_server(true);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut conn =
            common::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None).await;

        let (response, _) = conn
            .exchange(
                Request::connect("_udp2")
                    .header("padding", PADDING_HEADER_VALUE)
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status, http::StatusCode::OK);
        assert_response_padding(&response.headers, PaddingState::Ignored);

        let hole_puncher = encode_udp_chunk(&server_address, &[1]);
        conn.send(futures::stream::iter(std::iter::once(hole_puncher)))
            .await;

        let mut total = 0;
        let mut buf = [0; 64 * 1024];
        while total < EXPECTED_MANGLED_UDP_LENGTH {
            match conn.recv(&mut buf).await {
                0 => break,
                n => total += n,
            }
        }
        assert_eq!(total, EXPECTED_MANGLED_UDP_LENGTH);
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn h3_udp_upload() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let server_address = run_udp_server(false);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut conn =
            common::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None).await;

        let (response, _) = conn
            .exchange(
                Request::connect("_udp2")
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status, http::StatusCode::OK);

        conn.send(
            common::make_stream_of_chunks(UDP_CONTENT_SIZE, Some(UDP_CHUNK_SIZE))
                .map(|x| encode_udp_chunk(&server_address, x)),
        )
        .await;

        let mut ack = [0; UDP_CHUNK_SIZE];
        assert_eq!(conn.recv(&mut ack).await, MANGLED_UDP_HEADER_LENGTH + 1);
    };

    tokio::select! {
        _ = common::run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

async fn make_h1_tunnel(
    endpoint_address: SocketAddr,
    server_address: String,
    padding: PaddingState,
) -> (
    Pin<Box<dyn Future<Output = ()>>>,
    Pin<Box<dyn Future<Output = impl AsyncRead + AsyncWrite + Unpin + Send>>>,
) {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, &endpoint_address, None).await;

    let (mut request_sender, conn) = hyper::client::conn::Builder::new()
        .handshake(stream)
        .await
        .unwrap();

    let conn_driver = async move { conn.await.unwrap() }.boxed();

    let exchange = async move {
        let mut request = Request::builder()
            .version(http::Version::HTTP_11)
            .method(http::Method::CONNECT)
            .uri(server_address);
        if padding.requested() {
            request = request.header("padding", PADDING_HEADER_VALUE);
        }
        let request = request.body(hyper::Body::empty()).unwrap();
        let response = request_sender.send_request(request).await.unwrap();
        info!("CONNECT response: {:?}", response);
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_response_padding(response.headers(), padding);

        hyper::upgrade::on(response).await.unwrap()
    }
    .boxed();

    (conn_driver, exchange)
}

async fn make_h2_tunnel(
    endpoint_address: SocketAddr,
    server_address: String,
    padding: PaddingState,
) -> (
    Pin<Box<dyn Future<Output = ()>>>,
    Pin<Box<dyn Future<Output = impl AsyncRead + AsyncWrite + Unpin + Send>>>,
) {
    let stream = common::establish_tls_connection(
        common::MAIN_DOMAIN_NAME,
        &endpoint_address,
        Some(net_utils::HTTP2_ALPN.as_bytes()),
    )
    .await;

    let (mut request_sender, conn) = hyper::client::conn::Builder::new()
        .http2_only(true)
        .handshake(stream)
        .await
        .unwrap();

    let conn_driver = async move { conn.await.unwrap() }.boxed();

    let exchange = async move {
        let mut request = Request::builder()
            .version(http::Version::HTTP_2)
            .method(http::Method::CONNECT)
            .uri(server_address);
        if padding.requested() {
            request = request.header("padding", PADDING_HEADER_VALUE);
        }
        let request = request.body(hyper::Body::empty()).unwrap();
        let response = request_sender.send_request(request).await.unwrap();
        info!("CONNECT response: {:?}", response);
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_response_padding(response.headers(), padding);

        hyper::upgrade::on(response).await.unwrap()
    }
    .boxed();

    (conn_driver, exchange)
}

fn assert_response_padding(headers: &http::HeaderMap, padding: PaddingState) {
    let value = headers.get("padding");
    assert_eq!(value.is_some(), padding.expected_in_response());
    if let Some(value) = value {
        assert!((30..63).contains(&value.as_bytes().len()));
        assert!(value.as_bytes()[..PADDING_HEADER_RANDOM_PREFIX_SIZE]
            .iter()
            .all(|byte| PADDING_HEADER_RANDOM_CHARACTERS.contains(byte)));
        assert!(value.as_bytes()[PADDING_HEADER_RANDOM_PREFIX_SIZE..]
            .iter()
            .all(|byte| *byte == b'~'));
    }
}

async fn read_unpadded_download(io: &mut (impl AsyncRead + Unpin)) {
    let mut content = Vec::new();
    io.read_to_end(&mut content).await.unwrap();
    assert_eq!(content.len(), TCP_CONTENT_SIZE);
    assert!(content.iter().all(|byte| *byte == 0));
}

async fn read_padded_download(io: &mut (impl AsyncRead + Unpin)) {
    let mut decoded_size = 0;
    for _ in 0..8 {
        let data = read_padded_frame(io).await;
        assert!(!data.is_empty());
        assert!(data.iter().all(|byte| *byte == 0));
        decoded_size += data.len();
    }

    let mut raw = Vec::new();
    io.read_to_end(&mut raw).await.unwrap();
    assert!(raw.iter().all(|byte| *byte == 0));
    assert_eq!(decoded_size + raw.len(), TCP_CONTENT_SIZE);
}

async fn write_padded_upload(io: &mut (impl AsyncWrite + Unpin)) {
    for chunk in make_padded_upload_chunks() {
        io.write_all(&chunk).await.unwrap();
    }
}

fn make_padded_upload_chunks() -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut data_size = 0;

    for (original_data_size, padding_size) in [
        (1, 0),
        (2, 1),
        (3, 2),
        (7, 3),
        (255, 17),
        (256, 63),
        (1024, 127),
        (u16::MAX as usize, u8::MAX),
    ] {
        let mut frame = BytesMut::with_capacity(3 + original_data_size + padding_size as usize);
        frame.put_u16(original_data_size as u16);
        frame.put_u8(padding_size);
        frame.resize(frame.len() + original_data_size, 0);
        frame.resize(frame.len() + padding_size as usize, 0);
        chunks.push(frame.to_vec());
        data_size += original_data_size;
    }

    let mut remaining = TCP_CONTENT_SIZE - data_size;
    let raw = vec![0; 64 * 1024];
    while remaining > 0 {
        let to_write = remaining.min(raw.len());
        chunks.push(raw[..to_write].to_vec());
        remaining -= to_write;
    }

    chunks
}

async fn read_padded_frame(io: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut header = [0; 3];
    io.read_exact(&mut header).await.unwrap();

    let original_data_size = u16::from_be_bytes([header[0], header[1]]) as usize;
    let mut original_data = vec![0; original_data_size];
    io.read_exact(&mut original_data).await.unwrap();

    let mut padding = vec![0; header[2] as usize];
    io.read_exact(&mut padding).await.unwrap();
    assert!(padding.iter().all(|byte| *byte == 0));

    original_data
}

async fn read_h3_padded_download(conn: &mut common::Http3Session) {
    let mut encoded = BytesMut::new();
    let mut decoded_size = 0;
    let mut decoded_frames = 0;
    let mut buffer = [0; 64 * 1024];

    while decoded_frames < 8 {
        while encoded.len() < 3 {
            let read = conn.recv(&mut buffer).await;
            assert_ne!(read, 0);
            encoded.extend_from_slice(&buffer[..read]);
        }

        let original_data_size = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
        let frame_size = 3 + original_data_size + encoded[2] as usize;
        while encoded.len() < frame_size {
            let read = conn.recv(&mut buffer).await;
            assert_ne!(read, 0);
            encoded.extend_from_slice(&buffer[..read]);
        }

        let frame = encoded.split_to(frame_size);
        assert_ne!(original_data_size, 0);
        assert!(frame[3..3 + original_data_size]
            .iter()
            .all(|byte| *byte == 0));
        assert!(frame[3 + original_data_size..]
            .iter()
            .all(|byte| *byte == 0));
        decoded_size += original_data_size;
        decoded_frames += 1;
    }

    assert!(encoded.iter().all(|byte| *byte == 0));
    decoded_size += encoded.len();
    loop {
        let read = conn.recv(&mut buffer).await;
        if read == 0 {
            break;
        }
        assert!(buffer[..read].iter().all(|byte| *byte == 0));
        decoded_size += read;
    }
    assert_eq!(decoded_size, TCP_CONTENT_SIZE);
}

async fn read_h3_padded_frame(conn: &mut common::Http3Session) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut buffer = [0; 1024];

    loop {
        if encoded.len() >= 3 {
            let original_data_size = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
            let frame_size = 3 + original_data_size + encoded[2] as usize;
            if encoded.len() >= frame_size {
                assert!(encoded[3 + original_data_size..frame_size]
                    .iter()
                    .all(|byte| *byte == 0));
                return encoded[3..3 + original_data_size].to_vec();
            }
        }

        let read = conn.recv(&mut buffer).await;
        assert_ne!(read, 0);
        encoded.extend_from_slice(&buffer[..read]);
    }
}

fn run_tcp_server(is_download: bool) -> SocketAddr {
    let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let _ = server.set_nonblocking(true);
    let server_addr = server.local_addr().unwrap();

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let server = TcpListener::from_std(server).unwrap();
            let (mut socket, peer) = server.accept().await.unwrap();
            info!("New connection from {}", peer);

            if is_download {
                let mut content = common::make_stream_of_chunks(TCP_CONTENT_SIZE, None);
                while let Some(chunk) = content.next().await {
                    socket.write_all(chunk).await.unwrap();
                }
            } else {
                let mut total = 0;
                let mut buf = [0; 64 * 1024];
                while total < TCP_CONTENT_SIZE {
                    match socket.read(&mut buf).await.unwrap() {
                        0 => break,
                        n => {
                            assert!(buf[..n].iter().all(|byte| *byte == 0));
                            total += n;
                        }
                    }
                }

                assert_eq!(total, TCP_CONTENT_SIZE);
                let ack = 1_u8;
                socket.write_all(&[ack]).await.unwrap();
            }

            socket.flush().await.unwrap();
        });
    });

    server_addr
}

fn run_udp_server(is_download: bool) -> SocketAddr {
    let server = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let _ = server.set_nonblocking(true);
    let server_addr = server.local_addr().unwrap();

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let server = UdpSocket::from_std(server).unwrap();
            if is_download {
                let mut buf = [0; UDP_CHUNK_SIZE];
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, 1);

                let mut content =
                    common::make_stream_of_chunks(UDP_CONTENT_SIZE, Some(UDP_CHUNK_SIZE));
                while let Some(chunk) = content.next().await {
                    server.send_to(chunk, peer).await.unwrap();
                }
            } else {
                let mut peer = None;
                let mut total = 0;
                let mut buf = [0; UDP_CHUNK_SIZE];
                while total < UDP_CONTENT_SIZE {
                    let (n, p) = server.recv_from(&mut buf).await.unwrap();
                    assert_eq!(*peer.get_or_insert(p), p);
                    total += n;
                }

                assert_eq!(total, UDP_CONTENT_SIZE);
                let ack = 1_u8;
                server.send_to(&[ack], peer.unwrap()).await.unwrap();
            }
        });
    });

    server_addr
}

fn encode_udp_chunk(destination: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    const APP_NAME: &str = "test";
    const SOURCE_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const SOURCE_PORT: u16 = 1234;

    let mut buffer = vec![];
    buffer.put_u32((2 * (16 + 2) + 1 + APP_NAME.len() + payload.len()) as u32);
    buffer.put_slice(&[0; 12]);
    buffer.put_slice(&SOURCE_IP.octets());
    buffer.put_u16(SOURCE_PORT);
    buffer.put_slice(&[0; 12]);
    buffer.put_slice(&match destination.ip() {
        IpAddr::V4(ip) => ip.octets(),
        _ => unreachable!(),
    });
    buffer.put_u16(destination.port());
    buffer.put_u8(APP_NAME.len() as u8);
    buffer.put_slice(APP_NAME.as_bytes());
    buffer.put_slice(payload);

    buffer
}
