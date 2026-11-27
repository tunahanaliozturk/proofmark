//! The 14 `basic` probes: single-object `PUT`, `GET`, `HEAD` and
//! `DELETE`, ranges, metadata and the common error responses.

use super::{
    Basis, Catch, Check, Citation, Expectation, Judgement, Probe, deviates, error_is, exchange,
    from_checks, status_is,
};
use crate::checksum::{base64, hex, md5};
use crate::fake::Fault;
use crate::session::{Call, Exchange, ProbeError, Session};

const READ: &str = "2026-11-25";
const GET_OBJECT: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html";
const PUT_OBJECT: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html";
const HEAD_OBJECT: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html";
const DELETE_OBJECTS: &str =
    "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html";
const ERRORS: &str =
    "https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html";
const INTEGRITY: &str =
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html";
const METADATA: &str = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html";
const FOLDERS: &str = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html";

const fn documented(
    statement: &'static str,
    url: &'static str,
    section: &'static str,
) -> Expectation {
    Expectation {
        statement,
        basis: Basis::Documented,
        citation: Citation {
            url,
            section,
            read: READ,
        },
    }
}

const fn loud(fault: Fault) -> Catch {
    Catch {
        fault,
        silent: false,
    }
}

const fn silent(fault: Fault) -> Catch {
    Catch {
        fault,
        silent: true,
    }
}

/// The MD5 `ETag` S3 gives a single-part plaintext object.
fn md5_etag(data: &[u8]) -> String {
    format!("\"{}\"", hex(&md5(data)))
}

fn put(
    session: &mut Session,
    label: &'static str,
    key: &str,
    body: Vec<u8>,
) -> Result<(), ProbeError> {
    let call = Call::new("PUT", session.bucket(), Some(key)).body(body);
    session.send(label, &call)?;
    Ok(())
}

fn send(
    session: &mut Session,
    label: &'static str,
    method: &'static str,
    key: &str,
) -> Result<(), ProbeError> {
    let call = Call::new(method, session.bucket(), Some(key));
    session.send(label, &call)?;
    Ok(())
}

/// The body a GET returned must be `want`. A store that said `200` to the
/// write and serves other bytes has lost data without an error: silent.
fn body_is(exchange: &Exchange, want: &[u8]) -> Check {
    let got = exchange.response.body();
    if got == want {
        return Ok(());
    }
    let detail = if got.len() == want.len() {
        let at = got.iter().zip(want).position(|(a, b)| a != b).unwrap_or(0);
        format!(
            "{} returned the right length but bytes differ from offset {at}",
            exchange.label
        )
    } else {
        format!(
            "{} returned {} bytes; expected {}",
            exchange.label,
            got.len(),
            want.len()
        )
    };
    Err(deviates(detail, true))
}

fn header_is(exchange: &Exchange, name: &str, want: &str, silent: bool) -> Check {
    match exchange.response.header(name) {
        Some(got) if got == want => Ok(()),
        Some(got) => Err(deviates(
            format!("{} {name} was {got:?}; expected {want:?}", exchange.label),
            silent,
        )),
        None => Err(deviates(
            format!("{} had no {name}; expected {want:?}", exchange.label),
            silent,
        )),
    }
}

/// The request bodies a probe sent, found again from its exchanges so the
/// judge stays a function of what was observed.
fn sent<'a>(exchanges: &'a [Exchange], label: &str) -> Result<&'a [u8], Judgement> {
    Ok(exchange(exchanges, label)?.request.body())
}

// basic.put-get

fn run_put_get(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(4096 + 123);
    put(session, "put", &key, data)?;
    send(session, "get", "GET", &key)
}

fn judge_put_get(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "put")?, 200)?;
        let get = exchange(ex, "get")?;
        status_is(get, 200)?;
        body_is(get, sent(ex, "put")?)?;
        let length = sent(ex, "put")?.len().to_string();
        header_is(get, "content-length", &length, false)
    })())
}

// basic.etag-is-md5

fn run_etag(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(1000);
    put(session, "put", &key, data)?;
    send(session, "head", "HEAD", &key)
}

fn judge_etag(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        let put = exchange(ex, "put")?;
        status_is(put, 200)?;
        let want = md5_etag(sent(ex, "put")?);
        header_is(put, "etag", &want, false)?;
        let head = exchange(ex, "head")?;
        status_is(head, 200)?;
        header_is(head, "etag", &want, false)
    })())
}

// basic.head

fn run_head(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(2500);
    put(session, "put", &key, data)?;
    send(session, "head", "HEAD", &key)
}

fn judge_head(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        let put = exchange(ex, "put")?;
        status_is(put, 200)?;
        let head = exchange(ex, "head")?;
        status_is(head, 200)?;
        let length = sent(ex, "put")?.len().to_string();
        header_is(head, "content-length", &length, false)?;
        // The same ETag the write returned; whether it is an MD5 is
        // basic.etag-is-md5's question.
        let etag = put
            .response
            .header("etag")
            .ok_or_else(|| deviates("put answered 200 with no ETag".to_owned(), false))?;
        header_is(head, "etag", etag, false)
    })())
}

// basic.user-metadata

const METADATA_SENT: [(&str, &str); 2] = [
    ("x-amz-meta-color", "blue"),
    ("x-amz-meta-Shape", "Round-Square"),
];

fn run_metadata(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(10);
    let mut call = Call::new("PUT", session.bucket(), Some(&key)).body(data);
    for (name, value) in METADATA_SENT {
        call = call.header(name, value);
    }
    session.send("put", &call)?;
    send(session, "head", "HEAD", &key)
}

fn judge_metadata(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "put")?, 200)?;
        let head = exchange(ex, "head")?;
        status_is(head, 200)?;
        for (name, value) in METADATA_SENT {
            header_is(head, name, value, true)?;
        }
        Ok(())
    })())
}

// basic.zero-byte

fn run_zero_byte(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("empty");
    put(session, "put", &key, Vec::new())?;
    send(session, "get", "GET", &key)
}

fn judge_zero_byte(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "put")?, 200)?;
        let get = exchange(ex, "get")?;
        if get.response.status() == 404 {
            return Err(deviates(
                "the empty PUT answered 200, then get answered 404".to_owned(),
                true,
            ));
        }
        status_is(get, 200)?;
        body_is(get, b"")?;
        header_is(get, "etag", &md5_etag(b""), false)
    })())
}

// basic.overwrite

fn run_overwrite(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let first = session.payload(300);
    let second = session.payload(200);
    put(session, "first put", &key, first)?;
    put(session, "second put", &key, second)?;
    send(session, "get", "GET", &key)
}

fn judge_overwrite(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "first put")?, 200)?;
        status_is(exchange(ex, "second put")?, 200)?;
        let get = exchange(ex, "get")?;
        status_is(get, 200)?;
        if get.response.body() == sent(ex, "first put")? {
            return Err(deviates(
                "get returned the first write; the second answered 200 and was dropped".to_owned(),
                true,
            ));
        }
        body_is(get, sent(ex, "second put")?)
    })())
}

// basic.missing-key

fn run_missing_key(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("never-written");
    send(session, "get", "GET", &key)
}

fn judge_missing_key(ex: &[Exchange]) -> Judgement {
    from_checks((|| error_is(exchange(ex, "get")?, 404, "NoSuchKey", false))())
}

// basic.missing-bucket

fn run_missing_bucket(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let call = Call::new("GET", &session.absent_bucket(), Some(&key));
    session.send("get", &call)?;
    Ok(())
}

fn judge_missing_bucket(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        error_is(exchange(ex, "get")?, 404, "NoSuchBucket", false)
    })())
}

// basic.delete-missing

fn run_delete_missing(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("never-written");
    send(session, "delete", "DELETE", &key)
}

fn judge_delete_missing(ex: &[Exchange]) -> Judgement {
    from_checks((|| status_is(exchange(ex, "delete")?, 204))())
}

// basic.range

const RANGE_LEN: usize = 100;

fn run_range(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(RANGE_LEN);
    put(session, "put", &key, data)?;
    for (label, range) in [
        ("get bytes=10-19", "bytes=10-19"),
        ("get bytes=-5", "bytes=-5"),
    ] {
        let call = Call::new("GET", session.bucket(), Some(&key)).header("range", range);
        session.send(label, &call)?;
    }
    Ok(())
}

fn judge_range(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "put")?, 200)?;
        let data = sent(ex, "put")?;
        let len = data.len();
        for (label, start, end) in [
            ("get bytes=10-19", 10, 19),
            ("get bytes=-5", len - 5, len - 1),
        ] {
            let get = exchange(ex, label)?;
            if get.response.status() == 200 {
                return Err(deviates(
                    format!("{label} answered 200, ignoring the range; expected 206"),
                    true,
                ));
            }
            status_is(get, 206)?;
            header_is(
                get,
                "content-range",
                &format!("bytes {start}-{end}/{len}"),
                true,
            )?;
            body_is(get, &data[start..=end])?;
        }
        Ok(())
    })())
}

// basic.range-unsatisfiable

fn run_range_unsatisfiable(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(RANGE_LEN);
    put(session, "put", &key, data)?;
    let call = Call::new("GET", session.bucket(), Some(&key)).header("range", "bytes=200-299");
    session.send("get bytes=200-299", &call)?;
    Ok(())
}

fn judge_range_unsatisfiable(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "put")?, 200)?;
        error_is(
            exchange(ex, "get bytes=200-299")?,
            416,
            "InvalidRange",
            true,
        )
    })())
}

// basic.content-md5-mismatch

fn run_content_md5(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(500);
    let other = session.payload(500);
    let call = Call::new("PUT", session.bucket(), Some(&key))
        .header("content-md5", &base64(&md5(&other)))
        .body(data);
    session.send("put", &call)?;
    send(session, "head", "HEAD", &key)
}

fn judge_content_md5(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        error_is(exchange(ex, "put")?, 400, "BadDigest", true)?;
        let head = exchange(ex, "head")?;
        if head.response.status() != 404 {
            return Err(deviates(
                format!(
                    "the refused put left an object: head answered {}",
                    head.response.status()
                ),
                true,
            ));
        }
        Ok(())
    })())
}

// basic.bad-signature

fn run_bad_signature(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(64);
    let call = Call::new("PUT", session.bucket(), Some(&key))
        .body(data)
        .signed_with_wrong_secret();
    session.send("put", &call)?;
    send(session, "head", "HEAD", &key)
}

fn judge_bad_signature(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        error_is(exchange(ex, "put")?, 403, "SignatureDoesNotMatch", true)?;
        let head = exchange(ex, "head")?;
        if head.response.status() != 404 {
            return Err(deviates(
                format!(
                    "the refused put left an object: head answered {}",
                    head.response.status()
                ),
                true,
            ));
        }
        Ok(())
    })())
}

// basic.expect-continue

fn run_expect_continue(session: &mut Session) -> Result<(), ProbeError> {
    let key = session.key("object");
    let data = session.payload(10 * 1024);
    let call = Call::new("PUT", session.bucket(), Some(&key))
        .header("expect", "100-continue")
        .body(data);
    session.send("put", &call)?;
    send(session, "get", "GET", &key)
}

fn judge_expect_continue(ex: &[Exchange]) -> Judgement {
    from_checks((|| {
        status_is(exchange(ex, "put")?, 200)?;
        let get = exchange(ex, "get")?;
        status_is(get, 200)?;
        body_is(get, sent(ex, "put")?)
    })())
}

pub(super) static PROBES: &[Probe] = &[
    Probe {
        id: "basic.put-get",
        feature: "basic",
        expectation: documented(
            "GET returns exactly the bytes a PUT stored, with Content-Length equal to their number",
            GET_OBJECT,
            "Description",
        ),
        requests: "PUT <key> with 4,219 random bytes, then GET <key>",
        catches: &[silent(Fault::TruncateObject)],
        run: run_put_get,
        judge: judge_put_get,
    },
    Probe {
        id: "basic.etag-is-md5",
        feature: "basic",
        expectation: documented(
            "the ETag of a plaintext object written by one PutObject is the quoted hex MD5 of its data, on the PUT response and on HEAD",
            INTEGRITY,
            "Using Content-MD5 and the ETag to verify uploaded objects",
        ),
        requests: "PUT <key> with 1,000 random bytes, then HEAD <key>",
        catches: &[loud(Fault::EtagNotMd5)],
        run: run_etag,
        judge: judge_etag,
    },
    Probe {
        id: "basic.head",
        feature: "basic",
        expectation: documented(
            "HEAD answers 200 with the object's Content-Length, the ETag the PUT returned, and no body",
            HEAD_OBJECT,
            "Description",
        ),
        requests: "PUT <key> with 2,500 random bytes, then HEAD <key>",
        catches: &[loud(Fault::HeadReportsZeroLength)],
        run: run_head,
        judge: judge_head,
    },
    Probe {
        id: "basic.user-metadata",
        feature: "basic",
        expectation: documented(
            "x-amz-meta-* headers sent with a PUT come back on HEAD with the same values",
            METADATA,
            "User-defined metadata",
        ),
        requests: "PUT <key> with x-amz-meta-color: blue and x-amz-meta-Shape: Round-Square, then HEAD <key>",
        catches: &[silent(Fault::DropUserMetadata)],
        run: run_metadata,
        judge: judge_metadata,
    },
    Probe {
        id: "basic.zero-byte",
        feature: "basic",
        expectation: documented(
            "an empty PUT stores a 0-byte object: GET answers 200 with no bytes and the MD5 ETag of nothing",
            FOLDERS,
            "Organizing objects in the Amazon S3 console by using folders",
        ),
        requests: "PUT <key> with an empty body, then GET <key>",
        catches: &[silent(Fault::ZeroByteNotStored)],
        run: run_zero_byte,
        judge: judge_zero_byte,
    },
    Probe {
        id: "basic.overwrite",
        feature: "basic",
        expectation: documented(
            "a second PUT to a key replaces the first: GET returns the last bytes written",
            PUT_OBJECT,
            "Description",
        ),
        requests: "PUT <key> with 300 random bytes, PUT <key> with 200 other bytes, then GET <key>",
        catches: &[silent(Fault::IgnoreOverwrite)],
        run: run_overwrite,
        judge: judge_overwrite,
    },
    Probe {
        id: "basic.missing-key",
        feature: "basic",
        expectation: documented(
            "GET of a key that does not exist answers 404 with an XML error body whose Code is NoSuchKey",
            ERRORS,
            "List of error codes",
        ),
        requests: "GET <key> that was never written",
        catches: &[loud(Fault::MissingKeyEmptyBody)],
        run: run_missing_key,
        judge: judge_missing_key,
    },
    Probe {
        id: "basic.missing-bucket",
        feature: "basic",
        expectation: documented(
            "GET of a key in a bucket that does not exist answers 404 NoSuchBucket",
            ERRORS,
            "List of error codes",
        ),
        requests: "GET /proofmark-<run id>-absent/<key>, a bucket the run never creates",
        catches: &[loud(Fault::MissingBucketIsNoSuchKey)],
        run: run_missing_bucket,
        judge: judge_missing_bucket,
    },
    Probe {
        id: "basic.delete-missing",
        feature: "basic",
        expectation: Expectation {
            statement: "DELETE of a key that does not exist answers 204. The DeleteObject reference does not say; DeleteObjects documents that a missing key is confirmed as deleted, and the single call is taken to behave the same, so the basis is observed",
            basis: Basis::Observed,
            citation: Citation {
                url: DELETE_OBJECTS,
                section: "Description",
                read: READ,
            },
        },
        requests: "DELETE <key> that was never written",
        catches: &[loud(Fault::DeleteMissingIs404)],
        run: run_delete_missing,
        judge: judge_delete_missing,
    },
    Probe {
        id: "basic.range",
        feature: "basic",
        expectation: documented(
            "GET with Range: bytes=10-19 answers 206 with Content-Range: bytes 10-19/<size> and those bytes; bytes=-5 returns the last 5",
            GET_OBJECT,
            "URI Request Parameters (Range)",
        ),
        requests: "PUT <key> with 100 random bytes, GET <key> with Range: bytes=10-19, GET <key> with Range: bytes=-5",
        catches: &[
            silent(Fault::IgnoreRange),
            silent(Fault::SuffixRangeFromStart),
        ],
        run: run_range,
        judge: judge_range,
    },
    Probe {
        id: "basic.range-unsatisfiable",
        feature: "basic",
        expectation: documented(
            "GET with a range that starts past the end answers 416 InvalidRange",
            ERRORS,
            "List of error codes",
        ),
        requests: "PUT <key> with 100 random bytes, then GET <key> with Range: bytes=200-299",
        catches: &[silent(Fault::UnsatisfiableRangeServesWhole)],
        run: run_range_unsatisfiable,
        judge: judge_range_unsatisfiable,
    },
    Probe {
        id: "basic.content-md5-mismatch",
        feature: "basic",
        expectation: documented(
            "a PUT whose Content-MD5 does not match its body fails with 400 BadDigest and stores nothing",
            INTEGRITY,
            "Using Content-MD5 when uploading objects",
        ),
        requests: "PUT <key> with 500 random bytes and the Content-MD5 of 500 other bytes, then HEAD <key>",
        catches: &[silent(Fault::IgnoreContentMd5)],
        run: run_content_md5,
        judge: judge_content_md5,
    },
    Probe {
        id: "basic.bad-signature",
        feature: "basic",
        expectation: documented(
            "a PUT signed with the wrong secret key fails with 403 SignatureDoesNotMatch and stores nothing",
            ERRORS,
            "List of error codes",
        ),
        requests: "PUT <key> with 64 random bytes, signed with a wrong secret key, then HEAD <key> signed correctly",
        catches: &[silent(Fault::IgnoreSignature)],
        run: run_bad_signature,
        judge: judge_bad_signature,
    },
    Probe {
        id: "basic.expect-continue",
        feature: "basic",
        expectation: documented(
            "a PUT with Expect: 100-continue, as in the PutObject examples, completes and stores its body",
            PUT_OBJECT,
            "Examples",
        ),
        requests: "PUT <key> with 10 KiB of random bytes and Expect: 100-continue, then GET <key>",
        catches: &[loud(Fault::RejectExpectContinue)],
        run: run_expect_continue,
        judge: judge_expect_continue,
    },
];
