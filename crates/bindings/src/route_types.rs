//! HTTP request and response types for route handlers.
//!
//! Route handlers receive an `HttpRequest` and return types implementing
//! `IntoRouteResponse`, which converts to an `HttpResponse`.
//!
//! Both types cross the wasm boundary using a simple length-prefixed binary wire format.
//!
//! ## Response wire format (little-endian)
//! ```text
//! [u16 status] [u32 num_headers] ([u32 key_len] [key] [u32 val_len] [val])* [body]
//! ```
//!
//! ## Request wire format (little-endian)
//! ```text
//! [u32 method_len] [method] [u32 path_len] [path]
//! [u32 num_headers] ([u32 key_len] [key] [u32 val_len] [val])*
//! [u32 num_path_params] ([u32 key_len] [key] [u32 val_len] [val])*
//! [u32 query_len] [query]
//! [body]
//! ```

use std::collections::HashMap;

/// Maximum number of headers or path params allowed in wire format decoding.
/// Prevents unbounded allocation from crafted payloads.
const MAX_WIRE_ITEMS: usize = 1024;

/// An HTTP request passed to route handlers.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub path_params: HashMap<String, String>,
    pub query: String,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get a cookie value by name.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie").and_then(|cookies| {
            cookies.split(';').find_map(|pair| {
                let pair = pair.trim();
                let (key, val) = pair.split_once('=')?;
                (key.trim() == name).then_some(val.trim())
            })
        })
    }

    /// Get a path parameter by name (e.g., `:id` in `/brick/:id`).
    pub fn path_param(&self, name: &str) -> Option<&str> {
        self.path_params.get(name).map(|s| s.as_str())
    }

    /// Get a query parameter by name.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, val) = pair.split_once('=')?;
            (key == name).then(|| urlencoding_decode(val))
        })
    }

    /// Parse the body as a URL-encoded form and get a field.
    pub fn form_field(&self, name: &str) -> Option<String> {
        let body_str = std::str::from_utf8(&self.body).ok()?;
        body_str.split('&').find_map(|pair| {
            let (key, val) = pair.split_once('=')?;
            (key == name).then(|| urlencoding_decode(val))
        })
    }

    /// Parse the body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Encode this request to bytes for the wasm boundary.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        write_length_prefixed(&mut buf, self.method.as_bytes());
        write_length_prefixed(&mut buf, self.path.as_bytes());

        buf.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        for (key, val) in &self.headers {
            write_length_prefixed(&mut buf, key.as_bytes());
            write_length_prefixed(&mut buf, val.as_bytes());
        }

        buf.extend_from_slice(&(self.path_params.len() as u32).to_le_bytes());
        for (key, val) in &self.path_params {
            write_length_prefixed(&mut buf, key.as_bytes());
            write_length_prefixed(&mut buf, val.as_bytes());
        }

        write_length_prefixed(&mut buf, self.query.as_bytes());

        buf.extend_from_slice(&self.body);
        buf
    }

    /// Decode a request from bytes received from the host.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let method = read_length_prefixed_str(bytes, &mut pos)?;
        let path = read_length_prefixed_str(bytes, &mut pos)?;

        let num_headers = read_u32(bytes, &mut pos)? as usize;
        if num_headers > MAX_WIRE_ITEMS {
            return None;
        }
        let mut headers = Vec::with_capacity(num_headers);
        for _ in 0..num_headers {
            let key = read_length_prefixed_str(bytes, &mut pos)?;
            let val = read_length_prefixed_str(bytes, &mut pos)?;
            headers.push((key, val));
        }

        let num_params = read_u32(bytes, &mut pos)? as usize;
        if num_params > MAX_WIRE_ITEMS {
            return None;
        }
        let mut path_params = HashMap::with_capacity(num_params);
        for _ in 0..num_params {
            let key = read_length_prefixed_str(bytes, &mut pos)?;
            let val = read_length_prefixed_str(bytes, &mut pos)?;
            path_params.insert(key, val);
        }

        let query = read_length_prefixed_str(bytes, &mut pos)?;

        let body = bytes[pos..].to_vec();

        Some(Self {
            method,
            path,
            headers,
            path_params,
            query,
            body,
        })
    }
}

/// Minimal percent-decoding for form/query values.
/// Collects decoded bytes first, then converts to UTF-8 to handle multi-byte sequences.
fn urlencoding_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        match b {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hi = chars.next().and_then(|c| (c as char).to_digit(16));
                let lo = chars.next().and_then(|c| (c as char).to_digit(16));
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    bytes.push((hi * 16 + lo) as u8);
                } else {
                    bytes.push(b'%');
                }
            }
            _ => bytes.push(b),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn write_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > bytes.len() {
        return None;
    }
    let val = u32::from_le_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]);
    *pos += 4;
    Some(val)
}

fn read_length_prefixed_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_u32(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&bytes[*pos..*pos + len]).into_owned();
    *pos += len;
    Some(s)
}

/// An HTTP response that crosses the wasm boundary.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Create a response with the given status code.
    pub fn status(code: u16) -> Self {
        Self {
            status: code,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header to the response.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    /// Set the body to HTML content.
    pub fn html(mut self, body: impl Into<String>) -> Self {
        self.headers
            .push(("content-type".into(), "text/html; charset=utf-8".into()));
        self.body = body.into().into_bytes();
        self
    }

    /// Set the body to plain text.
    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.headers
            .push(("content-type".into(), "text/plain; charset=utf-8".into()));
        self.body = body.into().into_bytes();
        self
    }

    /// Set the body to JSON content.
    pub fn json(mut self, body: impl Into<String>) -> Self {
        self.headers
            .push(("content-type".into(), "application/json".into()));
        self.body = body.into().into_bytes();
        self
    }

    /// Set a raw byte body.
    pub fn body_bytes(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Encode this response to bytes for the wasm boundary.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.status.to_le_bytes());
        buf.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        for (key, val) in &self.headers {
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
            buf.extend_from_slice(val.as_bytes());
        }
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Decode a response from bytes received from the wasm boundary.
    /// Returns `None` if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0;

        if bytes.len() < 6 {
            return None;
        }

        let status = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        let num_headers =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;

        if num_headers > MAX_WIRE_ITEMS {
            return None;
        }
        let mut headers = Vec::with_capacity(num_headers);
        for _ in 0..num_headers {
            if pos + 4 > bytes.len() {
                return None;
            }
            let key_len = u32::from_le_bytes([
                bytes[pos],
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
            ]) as usize;
            pos += 4;

            if pos + key_len > bytes.len() {
                return None;
            }
            let key = String::from_utf8_lossy(&bytes[pos..pos + key_len]).into_owned();
            pos += key_len;

            if pos + 4 > bytes.len() {
                return None;
            }
            let val_len = u32::from_le_bytes([
                bytes[pos],
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
            ]) as usize;
            pos += 4;

            if pos + val_len > bytes.len() {
                return None;
            }
            let val = String::from_utf8_lossy(&bytes[pos..pos + val_len]).into_owned();
            pos += val_len;

            headers.push((key, val));
        }

        let body = bytes[pos..].to_vec();

        Some(Self {
            status,
            headers,
            body,
        })
    }
}

/// Trait for types that can be converted into an HTTP response.
pub trait IntoRouteResponse {
    fn into_route_response(self) -> HttpResponse;
}

impl IntoRouteResponse for HttpResponse {
    fn into_route_response(self) -> HttpResponse {
        self
    }
}

impl IntoRouteResponse for String {
    fn into_route_response(self) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: self.into_bytes(),
        }
    }
}

impl IntoRouteResponse for &str {
    fn into_route_response(self) -> HttpResponse {
        self.to_owned().into_route_response()
    }
}

/// HTML response (200 OK, text/html).
pub struct Html(pub String);

impl IntoRouteResponse for Html {
    fn into_route_response(self) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: self.0.into_bytes(),
        }
    }
}

/// JSON response (200 OK, application/json).
///
/// The type parameter must implement `serde::Serialize`.
pub struct Json<T>(pub T);

impl<T: serde::Serialize> IntoRouteResponse for Json<T> {
    fn into_route_response(self) -> HttpResponse {
        match serde_json::to_vec(&self.0) {
            Ok(body) => HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body,
            },
            Err(e) => HttpResponse {
                status: 500,
                headers: vec![("content-type".into(), "application/json".into())],
                body: format!("{{\"error\":\"serialization failed: {e}\"}}").into_bytes(),
            },
        }
    }
}

/// Redirect response (303 See Other).
pub struct Redirect(String);

impl Redirect {
    /// Create a redirect to the given URL (303 See Other).
    pub fn to(url: impl Into<String>) -> Self {
        Self(url.into())
    }
}

impl IntoRouteResponse for Redirect {
    fn into_route_response(self) -> HttpResponse {
        HttpResponse {
            status: 303,
            headers: vec![("location".into(), self.0)],
            body: Vec::new(),
        }
    }
}

/// Implement `IntoRouteResponse` for `Result<T, E>` where both implement it.
impl<T: IntoRouteResponse, E: IntoRouteResponse> IntoRouteResponse for Result<T, E> {
    fn into_route_response(self) -> HttpResponse {
        match self {
            Ok(v) => v.into_route_response(),
            Err(e) => e.into_route_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HttpResponse encode/decode ---

    #[test]
    fn response_round_trip_simple() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<h1>Hello</h1>".to_vec(),
        };
        let encoded = resp.encode();
        let decoded = HttpResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.headers.len(), 1);
        assert_eq!(decoded.headers[0].0, "content-type");
        assert_eq!(decoded.headers[0].1, "text/html");
        assert_eq!(decoded.body, b"<h1>Hello</h1>");
    }

    #[test]
    fn response_round_trip_no_headers() {
        let resp = HttpResponse::status(404).body_bytes(b"Not found".to_vec());
        let encoded = resp.encode();
        let decoded = HttpResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.status, 404);
        assert_eq!(decoded.headers.len(), 0);
        assert_eq!(decoded.body, b"Not found");
    }

    #[test]
    fn response_round_trip_multiple_headers() {
        let resp = HttpResponse::status(200)
            .header("x-custom", "value1")
            .header("set-cookie", "session=abc");
        let encoded = resp.encode();
        let decoded = HttpResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.headers.len(), 2);
        assert_eq!(decoded.headers[0], ("x-custom".into(), "value1".into()));
        assert_eq!(decoded.headers[1], ("set-cookie".into(), "session=abc".into()));
    }

    #[test]
    fn response_round_trip_empty_body() {
        let resp = HttpResponse::status(303).header("location", "/");
        let encoded = resp.encode();
        let decoded = HttpResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.status, 303);
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn response_decode_too_short() {
        assert!(HttpResponse::decode(&[]).is_none());
        assert!(HttpResponse::decode(&[0, 0]).is_none());
        assert!(HttpResponse::decode(&[0, 0, 0]).is_none());
    }

    // --- HttpRequest encode/decode ---

    #[test]
    fn request_round_trip_simple() {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/hello".into(),
            headers: vec![("host".into(), "localhost".into())],
            path_params: HashMap::new(),
            query: String::new(),
            body: Vec::new(),
        };
        let encoded = req.encode();
        let decoded = HttpRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.method, "GET");
        assert_eq!(decoded.path, "/hello");
        assert_eq!(decoded.headers.len(), 1);
        assert_eq!(decoded.headers[0].0, "host");
        assert!(decoded.path_params.is_empty());
        assert!(decoded.query.is_empty());
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn request_round_trip_with_params() {
        let mut params = HashMap::new();
        params.insert("id".into(), "42".into());
        let req = HttpRequest {
            method: "GET".into(),
            path: "/brick/42".into(),
            headers: Vec::new(),
            path_params: params,
            query: "format=json".into(),
            body: Vec::new(),
        };
        let encoded = req.encode();
        let decoded = HttpRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.path_param("id"), Some("42"));
        assert_eq!(decoded.query_param("format"), Some("json".to_string()));
    }

    #[test]
    fn request_round_trip_with_body() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/brick".into(),
            headers: vec![("content-type".into(), "application/x-www-form-urlencoded".into())],
            path_params: HashMap::new(),
            query: String::new(),
            body: b"x=5&y=3".to_vec(),
        };
        let encoded = req.encode();
        let decoded = HttpRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.form_field("x"), Some("5".to_string()));
        assert_eq!(decoded.form_field("y"), Some("3".to_string()));
        assert_eq!(decoded.form_field("z"), None);
    }

    // --- HttpRequest convenience methods ---

    #[test]
    fn request_header_case_insensitive() {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("Content-Type".into(), "text/html".into())],
            path_params: HashMap::new(),
            query: String::new(),
            body: Vec::new(),
        };
        assert_eq!(req.header("content-type"), Some("text/html"));
        assert_eq!(req.header("CONTENT-TYPE"), Some("text/html"));
        assert_eq!(req.header("x-missing"), None);
    }

    #[test]
    fn request_cookie_parsing() {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("cookie".into(), "session=abc123; theme=dark".into())],
            path_params: HashMap::new(),
            query: String::new(),
            body: Vec::new(),
        };
        assert_eq!(req.cookie("session"), Some("abc123"));
        assert_eq!(req.cookie("theme"), Some("dark"));
        assert_eq!(req.cookie("missing"), None);
    }

    #[test]
    fn request_query_param_decoding() {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: Vec::new(),
            path_params: HashMap::new(),
            query: "name=hello+world&key=a%20b".into(),
            body: Vec::new(),
        };
        assert_eq!(req.query_param("name"), Some("hello world".to_string()));
        assert_eq!(req.query_param("key"), Some("a b".to_string()));
    }

    #[test]
    fn request_form_field_decoding() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: Vec::new(),
            path_params: HashMap::new(),
            query: String::new(),
            body: b"name=hello+world&x=10".to_vec(),
        };
        assert_eq!(req.form_field("name"), Some("hello world".to_string()));
        assert_eq!(req.form_field("x"), Some("10".to_string()));
    }

    #[test]
    fn request_json_parsing() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: Vec::new(),
            path_params: HashMap::new(),
            query: String::new(),
            body: b"{\"x\":5,\"y\":3}".to_vec(),
        };
        let val: serde_json::Value = req.json().unwrap();
        assert_eq!(val["x"], 5);
        assert_eq!(val["y"], 3);
    }

    // --- IntoRouteResponse implementations ---

    #[test]
    fn string_into_response() {
        let resp = "Hello".to_string().into_route_response();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"Hello");
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v.contains("text/html")));
    }

    #[test]
    fn html_into_response() {
        let resp = Html("<h1>Hi</h1>".into()).into_route_response();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"<h1>Hi</h1>");
    }

    #[test]
    fn json_into_response() {
        let resp = Json(serde_json::json!({"key": "val"})).into_route_response();
        assert_eq!(resp.status, 200);
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v == "application/json"));
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed["key"], "val");
    }

    #[test]
    fn redirect_into_response() {
        let resp = Redirect::to("/home").into_route_response();
        assert_eq!(resp.status, 303);
        assert!(resp.headers.iter().any(|(k, v)| k == "location" && v == "/home"));
        assert!(resp.body.is_empty());
    }

    #[test]
    fn result_ok_into_response() {
        let result: Result<Html, HttpResponse> = Ok(Html("<p>ok</p>".into()));
        let resp = result.into_route_response();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"<p>ok</p>");
    }

    #[test]
    fn result_err_into_response() {
        let result: Result<Html, HttpResponse> = Err(HttpResponse::status(404).text("Not found"));
        let resp = result.into_route_response();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.body, b"Not found");
    }

    // --- HttpResponse builder ---

    #[test]
    fn response_builder_chain() {
        let resp = HttpResponse::status(418)
            .header("x-teapot", "yes")
            .html("<p>I'm a teapot</p>");
        assert_eq!(resp.status, 418);
        assert_eq!(resp.body, b"<p>I'm a teapot</p>");
        assert!(resp.headers.iter().any(|(k, v)| k == "x-teapot" && v == "yes"));
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v.contains("text/html")));
    }

    // --- URL decoding ---

    #[test]
    fn urlencoding_basic() {
        assert_eq!(urlencoding_decode("hello+world"), "hello world");
        assert_eq!(urlencoding_decode("a%20b"), "a b");
        assert_eq!(urlencoding_decode("100%25"), "100%");
        assert_eq!(urlencoding_decode("plain"), "plain");
    }

    #[test]
    fn urlencoding_multibyte_utf8() {
        // e with accent = U+00E9 = 0xC3 0xA9 in UTF-8
        assert_eq!(urlencoding_decode("caf%C3%A9"), "caf\u{00E9}");
        assert_eq!(urlencoding_decode("%C3%A9"), "\u{00E9}");
        // CJK character: U+4E16 = 0xE4 0xB8 0x96
        assert_eq!(urlencoding_decode("%E4%B8%96"), "\u{4E16}");
    }

    #[test]
    fn response_decode_too_many_headers() {
        // Craft bytes with num_headers = 0xFFFFFFFF
        let mut bytes = vec![200u8, 0]; // status 200
        bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // num_headers
        assert!(HttpResponse::decode(&bytes).is_none());
    }

    #[test]
    fn request_decode_too_many_headers() {
        let mut bytes = Vec::new();
        // method
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(b"GET");
        // path
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(b"/");
        // num_headers = huge
        bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        assert!(HttpRequest::decode(&bytes).is_none());
    }
}
