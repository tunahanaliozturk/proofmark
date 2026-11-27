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

fn parse<'a>(body: &'a [u8], what: &str) -> Result<roxmltree::Document<'a>, String> {
    let text = std::str::from_utf8(body).map_err(|_| format!("the {what} is not UTF-8"))?;
    roxmltree::Document::parse(text).map_err(|e| format!("the {what} is not XML: {e}"))
}

/// Whether a listing whose root element must be `root`, such as
/// `ListVersionsResult` or `ListMultipartUploadsResult`, lists nothing at
/// all. Only a whole listing of the right kind that says so counts: it
/// must carry `IsTruncated` set to `false`, and name no entry.
///
/// # Errors
///
/// A description of what was wrong if the body is not such a listing. The
/// caller must then treat the bucket as not shown to be empty.
pub fn listing_is_empty(body: &[u8], root: &str) -> Result<bool, String> {
    let doc = parse(body, "listing")?;
    let got = doc.root_element();
    if got.tag_name().name() != root {
        return Err(format!(
            "expected <{root}>, got <{}>",
            got.tag_name().name()
        ));
    }
    let mut empty = true;
    let mut complete = None;
    for child in got.children().filter(roxmltree::Node::is_element) {
        let text = child.text().unwrap_or_default().trim();
        match child.tag_name().name() {
            "Contents" | "Version" | "DeleteMarker" | "Upload" | "CommonPrefixes" => empty = false,
            "KeyCount" if text != "0" => empty = false,
            "IsTruncated" => complete = Some(text.eq_ignore_ascii_case("false")),
            _ => {}
        }
    }
    match complete {
        None => Err("the listing has no IsTruncated, so it may not be whole".to_owned()),
        Some(complete) => Ok(empty && complete),
    }
}

/// The `Status` of a `GetBucketVersioning` response: `None` for a bucket
/// whose versioning was never turned on, which has no `Status`.
///
/// # Errors
///
/// A description of what was wrong if the body is not a versioning
/// configuration.
pub fn versioning_status(body: &[u8]) -> Result<Option<String>, String> {
    let doc = parse(body, "versioning configuration")?;
    let root = doc.root_element();
    if root.tag_name().name() != "VersioningConfiguration" {
        return Err(format!(
            "expected <VersioningConfiguration>, got <{}>",
            root.tag_name().name()
        ));
    }
    Ok(root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Status")
        .map(|n| n.text().unwrap_or_default().trim().to_owned()))
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
        let (versions, uploads) = ("ListVersionsResult", "ListMultipartUploadsResult");
        let ns = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
        let empty = format!(
            "<ListVersionsResult {ns}><Name>b</Name><IsTruncated>false</IsTruncated></ListVersionsResult>"
        );
        assert_eq!(listing_is_empty(empty.as_bytes(), versions), Ok(true));
        assert!(listing_is_empty(empty.as_bytes(), uploads).is_err());
        let one = format!(
            "<ListVersionsResult {ns}><IsTruncated>false</IsTruncated><DeleteMarker><Key>k</Key></DeleteMarker></ListVersionsResult>"
        );
        assert_eq!(listing_is_empty(one.as_bytes(), versions), Ok(false));
        let truncated = "<ListVersionsResult><IsTruncated>true</IsTruncated></ListVersionsResult>";
        assert_eq!(listing_is_empty(truncated.as_bytes(), versions), Ok(false));
        let counted = "<ListVersionsResult><IsTruncated>false</IsTruncated><KeyCount>3</KeyCount></ListVersionsResult>";
        assert_eq!(listing_is_empty(counted.as_bytes(), versions), Ok(false));
        let upload = "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>k</Key></Upload></ListMultipartUploadsResult>";
        assert_eq!(listing_is_empty(upload.as_bytes(), uploads), Ok(false));
        assert!(listing_is_empty(b"<ListVersionsResult/>", versions).is_err());
        assert!(listing_is_empty(b"<Error><Code>AccessDenied</Code></Error>", versions).is_err());
        assert!(listing_is_empty(b"", versions).is_err());
    }

    #[test]
    fn reads_the_versioning_status() {
        let never = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
        assert_eq!(versioning_status(never.as_bytes()), Ok(None));
        let on = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
        assert_eq!(
            versioning_status(on.as_bytes()),
            Ok(Some("Enabled".to_owned()))
        );
        assert!(versioning_status(b"<Error/>").is_err());
    }

    #[test]
    fn encodes_bucket_and_key_paths() {
        assert_eq!(path("b", None), "/b");
        assert_eq!(path("b", Some("a b/c+d")), "/b/a%20b/c%2Bd");
    }
}
