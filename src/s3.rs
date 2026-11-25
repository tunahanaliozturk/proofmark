//! What proofmark reads out of S3 responses: error codes and whether a
//! listing is empty. Pure; the network is elsewhere.

use crate::sigv4::{encode_component, encode_path};

/// The path of a bucket, or of an object in it, in path-style addressing,
/// percent-encoded the way the signer expects.
#[must_use]
pub fn path(bucket: &str, key: Option<&str>) -> String {
    let mut path = format!("/{}", encode_component(bucket.as_bytes()));
    if let Some(key) = key {
        path.push('/');
        path.push_str(&encode_path(key.as_bytes()));
    }
    path
}

/// The `<Code>` of an S3 XML error body, if the body is one.
///
/// Only a code made of letters, digits and dots is returned. A code is the
/// one piece of an error body that goes into reports, and this keeps
/// anything a store chose to echo there, such as a signature, out of them.
#[must_use]
pub fn error_code(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "Error" {
        return None;
    }
    let code = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Code")?
        .text()?
        .trim();
    let plain = !code.is_empty()
        && code.len() <= 64
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.');
    plain.then(|| code.to_owned())
}

/// Whether a `ListObjectsV2`, `ListObjectVersions` or
/// `ListMultipartUploads` response lists nothing at all.
///
/// # Errors
///
/// A description of what was wrong if the body is not an XML listing. The
/// caller must then treat the bucket as not shown to be empty.
pub fn listing_is_empty(body: &[u8]) -> Result<bool, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the listing is not UTF-8".to_owned())?;
    let doc =
        roxmltree::Document::parse(text).map_err(|e| format!("the listing is not XML: {e}"))?;
    let root = doc.root_element();
    let known = [
        "ListBucketResult",
        "ListVersionsResult",
        "ListMultipartUploadsResult",
    ];
    if !known.contains(&root.tag_name().name()) {
        return Err(format!(
            "expected a listing, got <{}>",
            root.tag_name().name()
        ));
    }
    let mut empty = true;
    for child in root.children().filter(roxmltree::Node::is_element) {
        let text = child.text().unwrap_or_default().trim();
        match child.tag_name().name() {
            "Contents" | "Version" | "DeleteMarker" | "Upload" | "CommonPrefixes" => empty = false,
            "KeyCount" if text != "0" => empty = false,
            "IsTruncated" if !text.eq_ignore_ascii_case("false") => empty = false,
            _ => {}
        }
    }
    Ok(empty)
}

/// Escapes the five XML special characters.
#[must_use]
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_error_code_and_nothing_else() {
        let body =
            b"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code><Message>x</Message></Error>";
        assert_eq!(error_code(body).as_deref(), Some("NoSuchKey"));
        assert_eq!(error_code(b"<Error><Code>a b</Code></Error>"), None);
        assert_eq!(error_code(b"<Other><Code>X</Code></Other>"), None);
        assert_eq!(error_code(b"not xml"), None);
        assert_eq!(error_code(b""), None);
    }

    #[test]
    fn an_empty_listing_is_empty_and_anything_listed_is_not() {
        let ns = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
        let empty = format!(
            "<ListBucketResult {ns}><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>"
        );
        assert_eq!(listing_is_empty(empty.as_bytes()), Ok(true));
        let one = format!(
            "<ListVersionsResult {ns}><IsTruncated>false</IsTruncated><DeleteMarker><Key>k</Key></DeleteMarker></ListVersionsResult>"
        );
        assert_eq!(listing_is_empty(one.as_bytes()), Ok(false));
        let truncated = "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>";
        assert_eq!(listing_is_empty(truncated.as_bytes()), Ok(false));
        let counted = "<ListBucketResult><KeyCount>3</KeyCount></ListBucketResult>";
        assert_eq!(listing_is_empty(counted.as_bytes()), Ok(false));
        let upload = "<ListMultipartUploadsResult><Upload><Key>k</Key></Upload></ListMultipartUploadsResult>";
        assert_eq!(listing_is_empty(upload.as_bytes()), Ok(false));
        assert!(listing_is_empty(b"<Error><Code>AccessDenied</Code></Error>").is_err());
        assert!(listing_is_empty(b"").is_err());
    }

    #[test]
    fn encodes_bucket_and_key_paths() {
        assert_eq!(path("b", None), "/b");
        assert_eq!(path("b", Some("a b/c+d")), "/b/a%20b/c%2Bd");
    }
}
