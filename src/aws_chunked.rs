//! The `aws-chunked` content encoding: the framing S3 clients use for
//! streaming uploads, signed or unsigned, with or without a trailer.
//!
//! This is not HTTP chunked transfer encoding. The framing is inside a body
//! sent with an ordinary `Content-Length`, and the store must remove it.
//! References: [SigV4
//! streaming](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html),
//! section "Defining the Chunk Body", and [streaming with
//! trailers](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming-trailers.html).
//!
//! Signed chunk: `<hex size>;chunk-signature=<sig>\r\n<data>\r\n`. Unsigned
//! chunk: `<hex size>\r\n<data>\r\n`. The final chunk has size 0 and no
//! data, and is followed by the trailer lines, if any, and an empty line.

use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Range;

use crate::sigv4::ChunkSigner;

const SIGNATURE_PREFIX: &str = "chunk-signature=";
const TRAILER_SIGNATURE: &str = "x-amz-trailer-signature";

/// Frames `data` in chunks of `chunk_size` (the last data chunk may be
/// shorter), then the final empty chunk, then `trailers`.
///
/// With a `signer`, every chunk carries its signature and, if there are
/// trailers, an `x-amz-trailer-signature` line follows them.
#[must_use]
pub fn encode(
    data: &[u8],
    chunk_size: NonZeroUsize,
    trailers: &[(String, String)],
    mut signer: Option<&mut ChunkSigner>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 128);
    let mut frame = |piece: &[u8], signer: Option<&mut ChunkSigner>| {
        out.extend_from_slice(format!("{:x}", piece.len()).as_bytes());
        if let Some(signer) = signer {
            out.extend_from_slice(b";");
            out.extend_from_slice(SIGNATURE_PREFIX.as_bytes());
            out.extend_from_slice(signer.sign_chunk(piece).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        if !piece.is_empty() {
            out.extend_from_slice(piece);
            out.extend_from_slice(b"\r\n");
        }
    };
    for piece in data.chunks(chunk_size.get()) {
        frame(piece, signer.as_deref_mut());
    }
    frame(&[], signer.as_deref_mut());
    for (name, value) in trailers {
        out.extend_from_slice(format!("{name}:{value}\r\n").as_bytes());
    }
    if let Some(signer) = signer
        && !trailers.is_empty()
    {
        let signature = signer.sign_trailer(trailers);
        out.extend_from_slice(format!("{TRAILER_SIGNATURE}:{signature}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// One chunk of a decoded body: where its data sits in
/// [`Decoded::data`], and its signature if it had one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    range: Range<usize>,
    signature: Option<String>,
}

impl Chunk {
    /// The chunk's data as a range of [`Decoded::data`].
    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// The `chunk-signature` value, if the chunk had one.
    #[must_use]
    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }
}

/// An `aws-chunked` body with the framing removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    data: Vec<u8>,
    chunks: Vec<Chunk>,
    trailers: Vec<(String, String)>,
    trailer_signature: Option<String>,
}

impl Decoded {
    /// The data, without framing.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The data, without framing, by value.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Every chunk, the final empty one included.
    #[must_use]
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// The trailer lines, except `x-amz-trailer-signature`.
    #[must_use]
    pub fn trailers(&self) -> &[(String, String)] {
        &self.trailers
    }

    /// The `x-amz-trailer-signature` value, if there was one.
    #[must_use]
    pub fn trailer_signature(&self) -> Option<&str> {
        self.trailer_signature.as_deref()
    }

    /// True if every chunk is signed and each signature, and the trailer
    /// signature when there are trailers, is the one `signer` computes.
    #[must_use]
    pub fn signatures_match(&self, signer: &mut ChunkSigner) -> bool {
        for chunk in &self.chunks {
            let Some(sent) = chunk.signature.as_deref() else {
                return false;
            };
            if signer.sign_chunk(&self.data[chunk.range.clone()]) != sent {
                return false;
            }
        }
        if self.trailers.is_empty() && self.trailer_signature.is_none() {
            return true;
        }
        self.trailer_signature.as_deref() == Some(signer.sign_trailer(&self.trailers).as_str())
    }
}

/// Why a body is not valid `aws-chunked` framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    offset: usize,
    reason: &'static str,
}

impl DecodeError {
    /// The byte offset in the body where decoding stopped.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid aws-chunked body at byte {}: {}",
            self.offset, self.reason
        )
    }
}

impl std::error::Error for DecodeError {}

struct Cursor<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn fail(&self, reason: &'static str) -> DecodeError {
        DecodeError {
            offset: self.pos,
            reason,
        }
    }

    fn line(&mut self) -> Result<&'a [u8], DecodeError> {
        let rest = &self.body[self.pos..];
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| self.fail("no CRLF"))?;
        self.pos += end + 2;
        Ok(&rest[..end])
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.body.len());
        let end = end.ok_or_else(|| self.fail("chunk longer than the body"))?;
        let piece = &self.body[self.pos..end];
        self.pos = end;
        Ok(piece)
    }
}

fn parse_size(text: &[u8]) -> Option<usize> {
    if text.is_empty() || text.len() > 16 || !text.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let text = std::str::from_utf8(text).ok()?;
    usize::try_from(u64::from_str_radix(text, 16).ok()?).ok()
}

/// Removes the framing from an `aws-chunked` body. Signed and unsigned
/// chunks are both accepted; whether signatures are required and correct
/// is for [`Decoded::signatures_match`] to say.
///
/// # Errors
///
/// [`DecodeError`] if the framing is malformed, a chunk runs past the end of
/// the body, or bytes follow the final empty line.
pub fn decode(body: &[u8]) -> Result<Decoded, DecodeError> {
    let mut cursor = Cursor { body, pos: 0 };
    let mut data = Vec::new();
    let mut chunks = Vec::new();
    loop {
        let header = cursor.line()?;
        let (size, signature) = match header.iter().position(|&b| b == b';') {
            Some(semi) => {
                let extension = std::str::from_utf8(&header[semi + 1..])
                    .ok()
                    .and_then(|ext| ext.strip_prefix(SIGNATURE_PREFIX))
                    .ok_or_else(|| cursor.fail("unknown chunk extension"))?;
                (&header[..semi], Some(extension.to_owned()))
            }
            None => (header, None),
        };
        let size = parse_size(size).ok_or_else(|| cursor.fail("bad chunk size"))?;
        let start = data.len();
        if size > 0 {
            data.extend_from_slice(cursor.take(size)?);
            if cursor.line()? != b"" {
                return Err(cursor.fail("chunk data not followed by CRLF"));
            }
        }
        chunks.push(Chunk {
            range: start..data.len(),
            signature,
        });
        if size == 0 {
            break;
        }
    }
    let mut trailers = Vec::new();
    let mut trailer_signature = None;
    loop {
        let line = cursor.line()?;
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(line).map_err(|_| cursor.fail("trailer is not UTF-8"))?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| cursor.fail("trailer without ':'"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case(TRAILER_SIGNATURE) {
            trailer_signature = Some(value.to_owned());
        } else {
            trailers.push((name.to_owned(), value.to_owned()));
        }
    }
    if cursor.pos != body.len() {
        return Err(cursor.fail("bytes after the final empty line"));
    }
    Ok(Decoded {
        data,
        chunks,
        trailers,
        trailer_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SplitMix64;

    fn size(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("non-zero")
    }

    #[test]
    fn encodes_the_documented_unsigned_frame_format() {
        let trailers = [("x-amz-checksum-crc32".to_owned(), "DUoRhQ==".to_owned())];
        let body = encode(b"hello world", size(5), &trailers, None);
        assert_eq!(
            body,
            b"5\r\nhello\r\n5\r\n worl\r\n1\r\nd\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n"
        );
    }

    #[test]
    fn encodes_an_empty_body_as_the_final_chunk_only() {
        assert_eq!(encode(b"", size(8), &[], None), b"0\r\n\r\n");
    }

    #[test]
    fn decode_reverses_encode_for_random_sizes() {
        let mut rng = SplitMix64::new(0x5eed);
        let chunk = 64;
        let mut lengths: Vec<usize> = vec![0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 3 * chunk];
        lengths.extend((0..200).map(|_| rng.below(5 * chunk)));
        for len in lengths {
            let data = rng.bytes(len);
            let trailers = if len % 2 == 0 {
                vec![("x-amz-checksum-crc32".to_owned(), "AAAAAA==".to_owned())]
            } else {
                Vec::new()
            };
            let decoded = decode(&encode(&data, size(chunk), &trailers, None)).expect("decodes");
            assert_eq!(decoded.data(), data, "length {len}");
            assert_eq!(decoded.trailers(), trailers);
            assert_eq!(
                decoded.chunks().len(),
                len.div_ceil(chunk) + 1,
                "length {len}"
            );
            assert!(decoded.chunks().iter().all(|c| c.signature().is_none()));
        }
    }

    #[test]
    fn decode_rejects_broken_framing() {
        for body in [
            &b""[..],
            b"0\r\n",
            b"5\r\nhell\r\n0\r\n\r\n",
            b"5\r\nhelloX\r\n0\r\n\r\n",
            b"zz\r\nhello\r\n0\r\n\r\n",
            b"5;other=1\r\nhello\r\n0\r\n\r\n",
            b"ffffffffffffffff\r\nhello\r\n0\r\n\r\n",
            b"0\r\nno-colon\r\n\r\n",
            b"0\r\n\r\nextra",
        ] {
            assert!(decode(body).is_err(), "{:?}", String::from_utf8_lossy(body));
        }
    }
}
