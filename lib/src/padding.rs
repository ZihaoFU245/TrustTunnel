//! Implements optional padding for TCP CONNECT streams.
//!
//! A client requests padding by including a `padding` header in its CONNECT
//! request.  A capable endpoint includes the same header in the successful
//! response.  Padding is enabled only when the header is present in both
//! messages; its value carries no protocol data.  The endpoint response value
//! contains 30 to 62 characters: a 16-character random prefix followed by
//! `~` characters. `~` after huffman coding can preserve its length, thus
//! making regular CONNECT request length similar to GET.
//!
//! Once negotiated, each direction independently frames its first eight
//! payload records.  Later payload bytes are sent without framing.  Payloads
//! larger than [`u16::MAX`] are split across records.  Each padded record has
//! this format:
//!
//! ```text
//! +------------------------------+-------------------+----------------+---------+
//! | Original data size (u16, BE) | Padding size (u8) | Original data  | Zeros   |
//! +------------------------------+-------------------+----------------+---------+
//! ```
//!
//! The padding size is selected uniformly from 0 through 255.  Graceful
//! stream-closing frames do not count as payload records and are not padded.
//! This is intended to obscure recognizable TLS traffic shapes and defend
//! against early traffic-shape analysis.

use crate::{log_utils, pipe};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;
use std::io;
use std::io::ErrorKind;

pub(crate) const HEADER_NAME: &str = "padding";

const PADDED_FRAME_LIMIT: usize = 8;
const FRAME_HEADER_SIZE: usize = 3;
const MAX_ORIGINAL_DATA_SIZE: usize = u16::MAX as usize;
const RESPONSE_HEADER_MIN_SIZE: usize = 30;
const RESPONSE_HEADER_LENGTH_RANGE: usize = 33;
const RESPONSE_HEADER_RANDOM_PREFIX_SIZE: usize = 16;
const HEADER_RANDOM_CHARACTERS: &[u8; 16] = b"!#$()+<>?@[]^`{}";
const HEADER_TAIL_CHARACTER: u8 = b'~';

/// Wraps the client-facing halves of a negotiated TCP CONNECT stream.
pub(crate) fn wrap(
    source: Box<dyn pipe::Source>,
    sink: Box<dyn pipe::Sink>,
) -> (Box<dyn pipe::Source>, Box<dyn pipe::Sink>) {
    (
        Box::new(PaddingSource::new(source)),
        Box::new(PaddingSink::new(sink)),
    )
}

/// Generates the server's padding negotiation header.
pub(crate) fn response_header() -> http::HeaderValue {
    let mut rng = rand::thread_rng();
    let length = RESPONSE_HEADER_MIN_SIZE + rng.gen_range(0..RESPONSE_HEADER_LENGTH_RANGE);
    let mut bytes = vec![HEADER_TAIL_CHARACTER; length];
    for byte in &mut bytes[..RESPONSE_HEADER_RANDOM_PREFIX_SIZE] {
        *byte = HEADER_RANDOM_CHARACTERS[rng.gen_range(0..HEADER_RANDOM_CHARACTERS.len())];
    }

    let mut value = http::HeaderValue::from_bytes(&bytes)
        .expect("the padding header contains only valid ASCII");
    value.set_sensitive(true);
    value
}

fn encode_frame(original_data: Bytes, padding_size: u8) -> Bytes {
    let original_data_size =
        u16::try_from(original_data.len()).expect("padded frame data is capped at u16::MAX");
    let mut encoded =
        BytesMut::with_capacity(FRAME_HEADER_SIZE + original_data.len() + padding_size as usize);
    encoded.put_u16(original_data_size);
    encoded.put_u8(padding_size);
    encoded.put(original_data);
    encoded.resize(encoded.len() + padding_size as usize, 0);
    encoded.freeze()
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ReadState {
    /// Waiting for byte 0: the high byte of the original data size.
    ReadDataSizeHigh,
    /// Waiting for byte 1: the low byte of the original data size.
    ReadDataSizeLow { high: u8 },
    /// Waiting for byte 2: the padding size.
    ReadPaddingSize { data_size: u16 },
    /// Forwarding original data while remembering how much padding follows it.
    ReadData {
        remaining: usize,
        padding_size: usize,
    },
    /// Discarding padding before the next frame.
    ReadPadding { remaining: usize },
    /// The first eight frames are complete; all remaining bytes are unframed.
    Raw,
}

/// Removes padding frames from the client-to-endpoint direction.
///
/// Encoded bytes are consumed from the underlying HTTP stream as soon as they
/// are parsed. The outer pipe therefore treats the decoded payload as already
/// flow-control-accounted and [`pipe::Source::consume`] becomes a no-op.
struct PaddingSource {
    inner: Box<dyn pipe::Source>,
    state: ReadState,
    completed_frames: usize,
}

impl PaddingSource {
    fn new(inner: Box<dyn pipe::Source>) -> Self {
        Self {
            inner,
            state: ReadState::ReadDataSizeHigh,
            completed_frames: 0,
        }
    }

    fn decode(&mut self, mut input: Bytes, output: &mut BytesMut) {
        while !input.is_empty() {
            match self.state {
                ReadState::ReadDataSizeHigh => {
                    self.state = ReadState::ReadDataSizeLow {
                        high: input.get_u8(),
                    };
                }
                ReadState::ReadDataSizeLow { high } => {
                    let data_size = u16::from_be_bytes([high, input.get_u8()]);
                    self.state = ReadState::ReadPaddingSize { data_size };
                }
                ReadState::ReadPaddingSize { data_size } => {
                    let padding_size = input.get_u8() as usize;
                    self.start_frame(data_size as usize, padding_size);
                }
                ReadState::ReadData {
                    remaining,
                    padding_size,
                } => {
                    let to_copy = remaining.min(input.len());
                    output.put(input.split_to(to_copy));
                    let remaining = remaining - to_copy;
                    if remaining > 0 {
                        self.state = ReadState::ReadData {
                            remaining,
                            padding_size,
                        };
                    } else {
                        self.finish_data(padding_size);
                    }
                }
                ReadState::ReadPadding { remaining } => {
                    let to_skip = remaining.min(input.len());
                    input.advance(to_skip);
                    let remaining = remaining - to_skip;
                    if remaining > 0 {
                        self.state = ReadState::ReadPadding { remaining };
                    } else {
                        self.finish_frame();
                    }
                }
                ReadState::Raw => {
                    output.put(input);
                    return;
                }
            }
        }
    }

    fn start_frame(&mut self, data_size: usize, padding_size: usize) {
        if data_size > 0 {
            self.state = ReadState::ReadData {
                remaining: data_size,
                padding_size,
            };
        } else {
            self.finish_data(padding_size);
        }
    }

    fn finish_data(&mut self, padding_size: usize) {
        if padding_size > 0 {
            self.state = ReadState::ReadPadding {
                remaining: padding_size,
            };
        } else {
            self.finish_frame();
        }
    }

    fn finish_frame(&mut self) {
        self.completed_frames += 1;
        self.state = if self.completed_frames >= PADDED_FRAME_LIMIT {
            ReadState::Raw
        } else {
            ReadState::ReadDataSizeHigh
        };
    }

    fn has_partial_frame(&self) -> bool {
        !matches!(self.state, ReadState::ReadDataSizeHigh | ReadState::Raw)
    }
}

#[async_trait]
impl pipe::Source for PaddingSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.inner.id()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        loop {
            match self.inner.read().await? {
                pipe::Data::Chunk(input) => {
                    let input_size = input.len();
                    let mut output = BytesMut::with_capacity(input_size);
                    self.decode(input, &mut output);
                    self.inner.consume(input_size)?;
                    if !output.is_empty() {
                        return Ok(pipe::Data::Chunk(output.freeze()));
                    }
                }
                pipe::Data::Eof if self.has_partial_frame() => {
                    return Err(io::Error::from(ErrorKind::UnexpectedEof));
                }
                pipe::Data::Eof => return Ok(pipe::Data::Eof),
            }
        }
    }

    fn consume(&mut self, _size: usize) -> io::Result<()> {
        Ok(())
    }
}

/// Adds padding frames to the endpoint-to-client direction.
///
/// Original data is accepted once its encoded frame is buffered. `flush`
/// drains that frame before later data or EOF reaches the HTTP stream.
struct PaddingSink {
    inner: Box<dyn pipe::Sink>,
    pending_frame: Bytes,
    encoded_frames: usize,
    /// The outer pipe requested EOF, but a buffered frame may still precede it.
    eof_pending: bool,
    /// EOF was forwarded to the underlying HTTP stream.
    eof_sent: bool,
}

impl PaddingSink {
    fn new(inner: Box<dyn pipe::Sink>) -> Self {
        Self {
            inner,
            pending_frame: Bytes::new(),
            encoded_frames: 0,
            eof_pending: false,
            eof_sent: false,
        }
    }

    fn write_pending_once(&mut self) -> io::Result<()> {
        if !self.pending_frame.is_empty() {
            self.pending_frame = self.inner.write(std::mem::take(&mut self.pending_frame))?;
        }
        Ok(())
    }

    async fn flush_pending_frame(&mut self) -> io::Result<()> {
        while !self.pending_frame.is_empty() {
            self.inner.wait_writable().await?;
            self.write_pending_once()?;
        }
        Ok(())
    }
}

#[async_trait]
impl pipe::Sink for PaddingSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.inner.id()
    }

    fn write(&mut self, mut data: Bytes) -> io::Result<Bytes> {
        if self.eof_pending {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Cannot write after EOF",
            ));
        }

        self.write_pending_once()?;
        if !self.pending_frame.is_empty() {
            return Ok(data);
        }

        if self.encoded_frames >= PADDED_FRAME_LIMIT || data.is_empty() {
            return self.inner.write(data);
        }

        let original_data = data.split_to(data.len().min(MAX_ORIGINAL_DATA_SIZE));
        self.pending_frame = encode_frame(original_data, rand::random());
        self.encoded_frames += 1;
        self.write_pending_once()?;
        Ok(data)
    }

    fn eof(&mut self) -> io::Result<()> {
        if self.eof_pending {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "EOF has already been requested",
            ));
        }
        self.eof_pending = true;
        Ok(())
    }

    async fn wait_writable(&mut self) -> io::Result<()> {
        self.inner.wait_writable().await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.flush_pending_frame().await?;
        if self.eof_pending && !self.eof_sent {
            self.inner.eof()?;
            self.eof_sent = true;
        }
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::{Sink as _, Source as _};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct TestSource {
        chunks: VecDeque<pipe::Data>,
        consumed: Arc<Mutex<usize>>,
    }

    struct TestSink {
        output: Arc<Mutex<Vec<u8>>>,
        max_write_size: usize,
        eof: Arc<Mutex<bool>>,
    }

    #[async_trait]
    impl pipe::Source for TestSource {
        fn id(&self) -> log_utils::IdChain<u64> {
            log_utils::IdChain::empty()
        }

        async fn read(&mut self) -> io::Result<pipe::Data> {
            Ok(self.chunks.pop_front().unwrap_or(pipe::Data::Eof))
        }

        fn consume(&mut self, size: usize) -> io::Result<()> {
            *self.consumed.lock().unwrap() += size;
            Ok(())
        }
    }

    #[async_trait]
    impl pipe::Sink for TestSink {
        fn id(&self) -> log_utils::IdChain<u64> {
            log_utils::IdChain::empty()
        }

        fn write(&mut self, mut data: Bytes) -> io::Result<Bytes> {
            let to_write = data.len().min(self.max_write_size);
            self.output
                .lock()
                .unwrap()
                .extend_from_slice(&data.split_to(to_write));
            Ok(data)
        }

        fn eof(&mut self) -> io::Result<()> {
            *self.eof.lock().unwrap() = true;
            Ok(())
        }

        async fn wait_writable(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn test_source(chunks: impl IntoIterator<Item = Bytes>) -> PaddingSource {
        PaddingSource::new(Box::new(TestSource {
            chunks: chunks.into_iter().map(pipe::Data::Chunk).collect(),
            consumed: Arc::new(Mutex::new(0)),
        }))
    }

    async fn read_all(source: &mut PaddingSource) -> io::Result<Bytes> {
        let mut output = BytesMut::new();
        loop {
            match source.read().await? {
                pipe::Data::Chunk(data) => output.put(data),
                pipe::Data::Eof => return Ok(output.freeze()),
            }
        }
    }

    #[test]
    fn response_header_has_expected_contents() {
        let mut values = std::collections::HashSet::new();
        for _ in 0..256 {
            let value = response_header();
            assert!((RESPONSE_HEADER_MIN_SIZE
                ..RESPONSE_HEADER_MIN_SIZE + RESPONSE_HEADER_LENGTH_RANGE)
                .contains(&value.len()));
            assert!(value.as_bytes()[..RESPONSE_HEADER_RANDOM_PREFIX_SIZE]
                .iter()
                .all(|byte| HEADER_RANDOM_CHARACTERS.contains(byte)));
            assert!(value.as_bytes()[RESPONSE_HEADER_RANDOM_PREFIX_SIZE..]
                .iter()
                .all(|byte| *byte == HEADER_TAIL_CHARACTER));
            assert!(value.is_sensitive());
            values.insert(value.as_bytes()[..RESPONSE_HEADER_RANDOM_PREFIX_SIZE].to_vec());
        }
        assert!(values.len() > 1);
    }

    #[test]
    fn read_state_advances_one_header_byte_at_a_time() {
        let mut source = test_source([]);
        let mut output = BytesMut::new();

        source.decode(Bytes::from_static(&[1]), &mut output);
        assert_eq!(source.state, ReadState::ReadDataSizeLow { high: 1 });

        source.decode(Bytes::from_static(&[2]), &mut output);
        assert_eq!(
            source.state,
            ReadState::ReadPaddingSize { data_size: 0x0102 }
        );

        source.decode(Bytes::from_static(&[3]), &mut output);
        assert_eq!(
            source.state,
            ReadState::ReadData {
                remaining: 0x0102,
                padding_size: 3
            }
        );
        assert!(output.is_empty());
    }

    #[test]
    fn frame_uses_big_endian_length_and_zero_padding() {
        let frame = encode_frame(Bytes::from_static(b"payload"), u8::MAX);
        assert_eq!(&frame[..3], &[0, 7, u8::MAX]);
        assert_eq!(&frame[3..10], b"payload");
        assert!(frame[10..].iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn frame_boundaries_round_trip() {
        for (payload_size, padding_size) in [
            (0, 0),
            (0, u8::MAX),
            (1, 0),
            (1, u8::MAX),
            (MAX_ORIGINAL_DATA_SIZE, 0),
            (MAX_ORIGINAL_DATA_SIZE, u8::MAX),
        ] {
            let payload = Bytes::from(vec![42; payload_size]);
            let frame = encode_frame(payload.clone(), padding_size);
            let mut source = test_source([frame]);
            assert_eq!(read_all(&mut source).await.unwrap(), payload);
        }
    }

    #[tokio::test]
    async fn decoder_handles_fragmented_and_coalesced_frames() {
        let mut encoded = BytesMut::new();
        for payload in [b"one".as_slice(), b"two", b"three"] {
            encoded.put(encode_frame(Bytes::copy_from_slice(payload), 2));
        }
        let encoded = encoded.freeze();
        let fragments = [
            encoded.slice(..1),
            encoded.slice(1..7),
            encoded.slice(7..encoded.len() - 1),
            encoded.slice(encoded.len() - 1..),
        ];
        let mut source = test_source(fragments);

        assert_eq!(
            read_all(&mut source).await.unwrap(),
            b"onetwothree".as_slice()
        );
    }

    #[tokio::test]
    async fn decoder_switches_to_raw_bytes_after_eight_frames() {
        let mut encoded = BytesMut::new();
        for _ in 0..PADDED_FRAME_LIMIT {
            encoded.put(encode_frame(Bytes::from_static(b"x"), 0));
        }
        encoded.put_slice(b"raw");
        let mut source = test_source([encoded.freeze()]);

        assert_eq!(
            read_all(&mut source).await.unwrap(),
            b"xxxxxxxxraw".as_slice()
        );
    }

    #[tokio::test]
    async fn decoder_counts_pure_padding_and_ignores_padding_contents() {
        let mut encoded = BytesMut::new();
        for _ in 0..PADDED_FRAME_LIMIT {
            encoded.put_u16(0);
            encoded.put_u8(1);
            encoded.put_u8(42);
        }
        encoded.put_slice(b"raw");
        let mut source = test_source([encoded.freeze()]);

        assert_eq!(read_all(&mut source).await.unwrap(), b"raw".as_slice());
    }

    #[tokio::test]
    async fn decoder_allows_clean_eof_before_eight_frames() {
        let frame = encode_frame(Bytes::from_static(b"x"), 0);
        let mut source = test_source([frame]);

        assert_eq!(read_all(&mut source).await.unwrap(), b"x".as_slice());
    }

    #[tokio::test]
    async fn decoder_rejects_partial_frame_at_eof() {
        for partial_frame in [
            Bytes::from_static(&[0]),
            Bytes::from_static(&[0, 4]),
            Bytes::from_static(&[0, 4, 0, 1, 2]),
            Bytes::from_static(&[0, 1, 2, 42]),
        ] {
            let mut source = test_source([partial_frame]);
            assert_eq!(
                read_all(&mut source).await.unwrap_err().kind(),
                ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn sink_handles_partial_writes_and_payload_larger_than_u16() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let eof = Arc::new(Mutex::new(false));
        let mut sink = PaddingSink::new(Box::new(TestSink {
            output: output.clone(),
            max_write_size: 7,
            eof: eof.clone(),
        }));
        let payload = Bytes::from(vec![1; MAX_ORIGINAL_DATA_SIZE + 1]);

        let tail = sink.write(payload).unwrap();
        assert_eq!(tail.len(), 1);
        sink.flush().await.unwrap();
        assert!(sink.write(tail).unwrap().is_empty());
        sink.eof().unwrap();
        assert!(!*eof.lock().unwrap());
        sink.flush().await.unwrap();
        assert!(*eof.lock().unwrap());

        let encoded = Bytes::from(output.lock().unwrap().clone());
        let mut source = test_source([encoded]);
        assert_eq!(
            read_all(&mut source).await.unwrap(),
            Bytes::from(vec![1; MAX_ORIGINAL_DATA_SIZE + 1])
        );
    }

    #[tokio::test]
    async fn sink_stops_framing_after_eight_frames() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut sink = PaddingSink::new(Box::new(TestSink {
            output: output.clone(),
            max_write_size: usize::MAX,
            eof: Arc::new(Mutex::new(false)),
        }));

        for _ in 0..PADDED_FRAME_LIMIT {
            assert!(sink.write(Bytes::from_static(b"x")).unwrap().is_empty());
        }
        assert!(sink.write(Bytes::from_static(b"raw")).unwrap().is_empty());
        sink.flush().await.unwrap();

        let encoded = Bytes::from(output.lock().unwrap().clone());
        let mut source = test_source([encoded]);
        assert_eq!(
            read_all(&mut source).await.unwrap(),
            b"xxxxxxxxraw".as_slice()
        );
    }

    #[tokio::test]
    async fn sink_does_not_frame_eof() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let eof = Arc::new(Mutex::new(false));
        let mut sink = PaddingSink::new(Box::new(TestSink {
            output: output.clone(),
            max_write_size: usize::MAX,
            eof: eof.clone(),
        }));

        sink.eof().unwrap();
        sink.flush().await.unwrap();

        assert!(output.lock().unwrap().is_empty());
        assert!(*eof.lock().unwrap());
        assert_eq!(sink.encoded_frames, 0);
    }
}
