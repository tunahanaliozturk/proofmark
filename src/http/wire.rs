//! Reading HTTP/1.1 messages off a byte stream: response heads for the
//! client, request heads for the fake server, and bodies for both.
//!
//! The peer may be hostile or broken. Every read is bounded: heads, lines
//! and header counts by constants, bodies by the caller's limit. A
//! malformed message is an error, never a panic, and the input running out
//! is an error, never a loop.

use std::io::{self, Read};

use super::HttpError;

/// Largest request or response head accepted, in bytes.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
/// Most header fields accepted in one head.
const MAX_HEADERS: usize = 128;
/// Longest chunk-size or trailer line accepted, in bytes.
const MAX_LINE: usize = 8 * 1024;
/// Bytes asked for in one read.
const READ_SIZE: usize = 16 * 1024;

/// How a message body is delimited (RFC 9112, section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No body.
    Empty,
    /// Exactly this many bytes.
    Length(u64),
    /// Chunked transfer coding.
    Chunked,
    /// Everything until the connection closes (responses only).
    UntilClose,
}

/// A parsed response status line and header fields.
#[derive(Debug)]
pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
}

/// A parsed request line and header fields.
#[derive(Debug)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// A buffered reader that keeps whatever it has read but not yet used, so
/// that a timed-out read can be resumed without losing bytes.
pub(crate) struct Wire<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
}

fn owned_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

impl<R: Read> Wire<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }

    pub(crate) fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Reads more bytes into the buffer. `Ok(false)` means end of stream.
    fn fill(&mut self) -> io::Result<bool> {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > READ_SIZE {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut chunk = [0u8; READ_SIZE];
        loop {
            match self.inner.read(&mut chunk) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn need_more(&mut self, limit: usize, what: &'static str) -> Result<(), HttpError> {
        if self.available().len() > limit {
            return Err(HttpError::Malformed(format!(
                "{what} longer than {limit} bytes"
            )));
        }
        if self.fill()? {
            Ok(())
        } else {
            Err(HttpError::UnexpectedEof)
        }
    }

    /// Reads one response head. Interim (`1xx`) responses are returned like
    /// any other; the caller decides what to do with them.
    pub(crate) fn response_head(&mut self) -> Result<ResponseHead, HttpError> {
        loop {
            let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut parsed = httparse::Response::new(&mut fields);
            let parsed = match parsed.parse(self.available()) {
                Ok(httparse::Status::Complete(len)) => Some((
                    len,
                    ResponseHead {
                        status: parsed.code.unwrap_or(0),
                        headers: owned_headers(parsed.headers),
                    },
                )),
                Ok(httparse::Status::Partial) => None,
                Err(e) => return Err(HttpError::Malformed(format!("response head: {e}"))),
            };
            if let Some((len, head)) = parsed {
                self.pos += len;
                if !(100..=999).contains(&head.status) {
                    return Err(HttpError::Malformed(format!("status {}", head.status)));
                }
                return Ok(head);
            }
            self.need_more(MAX_HEAD, "response head")?;
        }
    }

    /// Reads one request head.
    pub(crate) fn request_head(&mut self) -> Result<RequestHead, HttpError> {
        loop {
            let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut parsed = httparse::Request::new(&mut fields);
            let parsed = match parsed.parse(self.available()) {
                Ok(httparse::Status::Complete(len)) => Some((
                    len,
                    RequestHead {
                        method: parsed.method.unwrap_or_default().to_owned(),
                        target: parsed.path.unwrap_or_default().to_owned(),
                        headers: owned_headers(parsed.headers),
                    },
                )),
                Ok(httparse::Status::Partial) => None,
                Err(e) => return Err(HttpError::Malformed(format!("request head: {e}"))),
            };
            if let Some((len, head)) = parsed {
                self.pos += len;
                return Ok(head);
            }
            self.need_more(MAX_HEAD, "request head")?;
        }
    }

    /// One line, CRLF included, of at most [`MAX_LINE`] bytes.
    fn line(&mut self) -> Result<Vec<u8>, HttpError> {
        loop {
            if let Some(end) = self.available().iter().position(|&b| b == b'\n') {
                let line = self.available()[..=end].to_vec();
                self.pos += end + 1;
                return Ok(line);
            }
            self.need_more(MAX_LINE, "line")?;
        }
    }

    /// Appends exactly `len` bytes to `out`.
    fn exact(&mut self, mut len: usize, out: &mut Vec<u8>) -> Result<(), HttpError> {
        while len > 0 {
            if self.available().is_empty() && !self.fill()? {
                return Err(HttpError::UnexpectedEof);
            }
            let take = len.min(self.available().len());
            out.extend_from_slice(&self.available()[..take]);
            self.pos += take;
            len -= take;
        }
        Ok(())
    }

    /// Reads a body delimited by `framing`, refusing more than `max` bytes.
    pub(crate) fn body(&mut self, framing: Framing, max: usize) -> Result<Vec<u8>, HttpError> {
        match framing {
            Framing::Empty => Ok(Vec::new()),
            Framing::Length(len) => {
                let len = usize::try_from(len).map_err(|_| HttpError::TooLarge)?;
                if len > max {
                    return Err(HttpError::TooLarge);
                }
                let mut out = Vec::with_capacity(len.min(READ_SIZE));
                self.exact(len, &mut out)?;
                Ok(out)
            }
            Framing::Chunked => self.chunked(max),
            Framing::UntilClose => self.until_close(max),
        }
    }

    fn chunked(&mut self, max: usize) -> Result<Vec<u8>, HttpError> {
        let mut out = Vec::new();
        loop {
            let line = self.line()?;
            let Ok(httparse::Status::Complete((_, size))) = httparse::parse_chunk_size(&line)
            else {
                return Err(HttpError::Malformed("chunk size line".to_owned()));
            };
            if size == 0 {
                break;
            }
            let size = usize::try_from(size).map_err(|_| HttpError::TooLarge)?;
            if size > max.saturating_sub(out.len()) {
                return Err(HttpError::TooLarge);
            }
            self.exact(size, &mut out)?;
            if self.line()? != b"\r\n" {
                return Err(HttpError::Malformed(
                    "chunk data not followed by CRLF".to_owned(),
                ));
            }
        }
        // Trailer fields are read and dropped; S3 does not send any that matter.
        let mut trailer_bytes = 0usize;
        loop {
            let line = self.line()?;
            if line == b"\r\n" || line == b"\n" {
                return Ok(out);
            }
            trailer_bytes += line.len();
            if trailer_bytes > MAX_HEAD {
                return Err(HttpError::Malformed("trailer section too large".to_owned()));
            }
        }
    }

    fn until_close(&mut self, max: usize) -> Result<Vec<u8>, HttpError> {
        let mut out = Vec::new();
        loop {
            out.extend_from_slice(self.available());
            self.pos = self.buf.len();
            if out.len() > max {
                return Err(HttpError::TooLarge);
            }
            match self.fill() {
                Ok(true) => {}
                // A TLS peer that closes without close_notify ends the body too.
                Ok(false) => return Ok(out),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(out),
                Err(e) => return Err(e.into()),
            }
        }
    }
}

fn values<'a>(headers: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The value of every `Content-Length` field, which must all agree.
fn content_length(headers: &[(String, String)]) -> Result<Option<u64>, HttpError> {
    let mut found = None;
    for field in values(headers, "content-length") {
        for value in field.split(',') {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::Malformed(format!("content-length {value:?}")));
            }
            let len: u64 = value.parse().map_err(|_| HttpError::TooLarge)?;
            if found.is_some_and(|previous| previous != len) {
                return Err(HttpError::Malformed(
                    "conflicting content-length".to_owned(),
                ));
            }
            found = Some(len);
        }
    }
    Ok(found)
}

/// True if the last transfer coding is `chunked`; `None` without the field.
fn ends_chunked(headers: &[(String, String)]) -> Option<bool> {
    let codings: Vec<&str> = values(headers, "transfer-encoding")
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect();
    if codings.is_empty() {
        return None;
    }
    Some(
        codings
            .last()
            .is_some_and(|c| c.eq_ignore_ascii_case("chunked")),
    )
}

/// How the body of a response to a request with `method` is delimited.
pub(crate) fn response_framing(
    status: u16,
    method: &str,
    headers: &[(String, String)],
) -> Result<Framing, HttpError> {
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Ok(Framing::Empty);
    }
    match ends_chunked(headers) {
        Some(true) => Ok(Framing::Chunked),
        Some(false) => Ok(Framing::UntilClose),
        None => Ok(content_length(headers)?.map_or(Framing::UntilClose, Framing::Length)),
    }
}

/// How the body of a request is delimited. Requests that carry both
/// `Transfer-Encoding` and `Content-Length`, or a transfer coding other
/// than chunked, are refused (RFC 9112, section 6.3).
pub(crate) fn request_framing(headers: &[(String, String)]) -> Result<Framing, HttpError> {
    let length = content_length(headers)?;
    match ends_chunked(headers) {
        Some(true) if length.is_none() => Ok(Framing::Chunked),
        Some(_) => Err(HttpError::Malformed(
            "unsupported request framing".to_owned(),
        )),
        None => Ok(length.map_or(Framing::Empty, Framing::Length)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn head_responses_and_bodiless_statuses_have_no_body() {
        let h = headers(&[("Content-Length", "10")]);
        assert_eq!(response_framing(200, "HEAD", &h).ok(), Some(Framing::Empty));
        assert_eq!(response_framing(204, "GET", &h).ok(), Some(Framing::Empty));
        assert_eq!(response_framing(304, "GET", &h).ok(), Some(Framing::Empty));
        assert_eq!(
            response_framing(200, "GET", &h).ok(),
            Some(Framing::Length(10))
        );
    }

    #[test]
    fn transfer_encoding_wins_over_content_length_in_responses() {
        let h = headers(&[
            ("Content-Length", "10"),
            ("Transfer-Encoding", "gzip, chunked"),
        ]);
        assert_eq!(
            response_framing(200, "GET", &h).ok(),
            Some(Framing::Chunked)
        );
        let h = headers(&[("Transfer-Encoding", "gzip")]);
        assert_eq!(
            response_framing(200, "GET", &h).ok(),
            Some(Framing::UntilClose)
        );
    }

    #[test]
    fn conflicting_lengths_are_malformed() {
        let h = headers(&[("Content-Length", "10"), ("Content-Length", "11")]);
        assert!(response_framing(200, "GET", &h).is_err());
        let h = headers(&[("Content-Length", "10, 10")]);
        assert_eq!(
            response_framing(200, "GET", &h).ok(),
            Some(Framing::Length(10))
        );
        let h = headers(&[("Content-Length", "-1")]);
        assert!(response_framing(200, "GET", &h).is_err());
    }

    #[test]
    fn requests_with_both_framings_are_refused() {
        let h = headers(&[("Content-Length", "3"), ("Transfer-Encoding", "chunked")]);
        assert!(request_framing(&h).is_err());
        assert_eq!(request_framing(&[]).ok(), Some(Framing::Empty));
    }

    #[test]
    fn reads_a_chunked_body_with_trailers() {
        let input = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nx-trailer: 1\r\n\r\n";
        let mut wire = Wire::new(&input[..]);
        assert_eq!(
            wire.body(Framing::Chunked, 100).ok(),
            Some(b"hello world".to_vec())
        );
    }

    #[test]
    fn refuses_a_body_over_the_limit_before_reading_it() {
        let mut wire = Wire::new(&b"tiny"[..]);
        assert!(matches!(
            wire.body(Framing::Length(u64::MAX), 1024),
            Err(HttpError::TooLarge)
        ));
        let mut wire = Wire::new(&b"ffffffff\r\n"[..]);
        assert!(matches!(
            wire.body(Framing::Chunked, 1024),
            Err(HttpError::TooLarge)
        ));
    }
}
