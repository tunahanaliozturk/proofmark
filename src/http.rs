//! Requests and responses as plain data. What a [`Request`] holds is what
//! goes on the wire, header for header, and a status code in a
//! [`Response`] is data, not an error. The client that sends them builds
//! on these types.

use crate::sigv4::encode_component;

/// One request, exactly as it will be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    /// A request with no query, no headers and no body. `path` is sent as
    /// given, so it must already be percent-encoded.
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The same request with one more query parameter, unencoded.
    #[must_use]
    pub fn with_query(mut self, key: &str, value: &str) -> Self {
        self.push_query(key, value);
        self
    }

    /// The same request with one more header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.push_header(name, value);
        self
    }

    /// The same request with `body`.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Appends a query parameter, unencoded.
    pub fn push_query(&mut self, key: &str, value: &str) {
        self.query.push((key.to_owned(), value.to_owned()));
    }

    /// Appends a header.
    pub fn push_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_owned(), value.to_owned()));
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The path, percent-encoded, as sent.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query parameters, unencoded, in send order.
    #[must_use]
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    /// The headers in send order.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The first header named `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The request target: the path, and the query encoded with SigV4's
    /// rules. A parameter with an empty value is sent as `key` alone, the
    /// way S3 sub-resources such as `?uploads` are written.
    #[must_use]
    pub fn target(&self) -> String {
        let mut target = self.path.clone();
        for (i, (key, value)) in self.query.iter().enumerate() {
            target.push(if i == 0 { '?' } else { '&' });
            target.push_str(&encode_component(key.as_bytes()));
            if !value.is_empty() {
                target.push('=');
                target.push_str(&encode_component(value.as_bytes()));
            }
        }
        target
    }
}

/// One response, with headers in received order and duplicates kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// A response, as the fake server builds them.
    #[must_use]
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The headers in received order.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The first header named `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

fn first<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_target_with_encoded_query() {
        let request = Request::new("GET", "/bucket/a%20b")
            .with_query("uploads", "")
            .with_query("prefix", "x/y z");
        assert_eq!(request.target(), "/bucket/a%20b?uploads&prefix=x%2Fy%20z");
    }
}
