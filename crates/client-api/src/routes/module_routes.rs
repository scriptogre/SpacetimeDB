//! HTTP fallback handler for module-defined routes.
//!
//! When a request doesn't match any built-in SpacetimeDB API route,
//! this handler checks if the default module has a matching route definition
//! and dispatches to the module's wasm route handler.

use axum::extract::State;
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::{ControlStateDelegate, NodeDelegate};
use spacetimedb_client_api_messages::name::DatabaseName;

use super::database::{find_leader_and_database, NameOrIdentity};

/// Get the default module name from the SPACETIMEDB_DEFAULT_MODULE env var.
fn default_module_name() -> Option<&'static str> {
    static DEFAULT_MODULE: OnceLock<Option<String>> = OnceLock::new();
    DEFAULT_MODULE
        .get_or_init(|| std::env::var("SPACETIMEDB_DEFAULT_MODULE").ok())
        .as_deref()
}

/// Resolve the default module: env var first, then sole published database.
async fn resolve_default_module<S: ControlStateDelegate>(ctx: &S) -> Option<NameOrIdentity> {
    if let Some(name) = default_module_name() {
        return Some(NameOrIdentity::Name(DatabaseName(name.to_owned())));
    }
    // If exactly one database is published, use it automatically.
    let databases = ctx.get_databases().await.ok()?;
    if databases.len() == 1 {
        Some(NameOrIdentity::Identity(databases[0].database_identity.into()))
    } else {
        None
    }
}

/// Axum fallback handler that dispatches to module-defined HTTP routes.
pub async fn module_route_fallback<S>(
    State(ctx): State<S>,
    method: Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response
where
    S: ControlStateDelegate + NodeDelegate + Clone + 'static,
{
    match handle_module_route(&ctx, &method, &uri, &headers, &body).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

async fn handle_module_route<S>(
    ctx: &S,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<Response, StatusCode>
where
    S: ControlStateDelegate + NodeDelegate + Clone + 'static,
{
    let name_or_identity = resolve_default_module(ctx).await.ok_or(StatusCode::NOT_FOUND)?;
    let path = uri.path();

    let (leader, _database) = find_leader_and_database(ctx, name_or_identity)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let module = leader.module().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let module_def = &module.info().module_def;
    let method_str = method.as_str();

    let (procedure_id, procedure_def) = module_def
        .find_route_procedure(method_str, path)
        .ok_or(StatusCode::NOT_FOUND)?;

    let procedure_name = procedure_def.name.clone();
    let route_path = procedure_def.route_path.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    // Extract path parameters by matching the route pattern against the actual path.
    let path_params = extract_path_params(route_path, path);

    // Encode the HTTP request for the wasm boundary.
    let request_bytes = encode_request(method_str, path, headers, &path_params, uri, body);

    let response_bytes = module
        .call_route_as_procedure(procedure_id, procedure_name, request_bytes)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    decode_route_response(&response_bytes)
}

/// Extract path parameters from a route pattern like `/brick/:id` matched against `/brick/42`.
fn extract_path_params(pattern: &str, path: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();

    for (pat, val) in pattern_parts.iter().zip(path_parts.iter()) {
        if let Some(name) = pat.strip_prefix(':') {
            params.insert(name.to_string(), val.to_string());
        }
    }
    params
}

/// Encode the HTTP request into the wire format expected by the wasm module.
///
/// Wire format (all u32/u16 are little-endian):
/// ```text
/// [u32 method_len] [method] [u32 path_len] [path]
/// [u32 num_headers] ([u32 key_len] [key] [u32 val_len] [val])*
/// [u32 num_path_params] ([u32 key_len] [key] [u32 val_len] [val])*
/// [u32 query_len] [query]
/// [body]
/// ```
fn encode_request(
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    path_params: &HashMap<String, String>,
    uri: &axum::http::Uri,
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();

    write_lp(&mut buf, method.as_bytes());
    write_lp(&mut buf, path.as_bytes());

    // Headers
    buf.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for (key, val) in headers.iter() {
        write_lp(&mut buf, key.as_str().as_bytes());
        write_lp(&mut buf, val.as_bytes());
    }

    // Path params
    buf.extend_from_slice(&(path_params.len() as u32).to_le_bytes());
    for (key, val) in path_params {
        write_lp(&mut buf, key.as_bytes());
        write_lp(&mut buf, val.as_bytes());
    }

    // Query
    let query = uri.query().unwrap_or("");
    write_lp(&mut buf, query.as_bytes());

    // Body
    buf.extend_from_slice(body);
    buf
}

fn write_lp(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Decode the wire-format response from the wasm module into an axum Response.
fn decode_route_response(bytes: &[u8]) -> Result<Response, StatusCode> {
    if bytes.len() < 6 {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut pos = 0;

    let status_code = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
    pos += 2;

    let num_headers =
        u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;

    // Cap header count to prevent unbounded allocation from malicious wasm modules.
    if num_headers > 1024 {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let mut decoded_headers = Vec::with_capacity(num_headers);
    for _ in 0..num_headers {
        if pos + 4 > bytes.len() {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let key_len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
        pos += 4;
        if pos + key_len > bytes.len() {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let key = String::from_utf8_lossy(&bytes[pos..pos + key_len]).into_owned();
        pos += key_len;

        if pos + 4 > bytes.len() {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let val_len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
        pos += 4;
        if pos + val_len > bytes.len() {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let val = String::from_utf8_lossy(&bytes[pos..pos + val_len]).into_owned();
        pos += val_len;

        decoded_headers.push((key, val));
    }

    let body = bytes[pos..].to_vec();

    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response = (status, body).into_response();

    for (key, val) in decoded_headers {
        if let (Ok(name), Ok(value)) = (
            header::HeaderName::from_bytes(key.as_bytes()),
            header::HeaderValue::from_str(&val),
        ) {
            response.headers_mut().insert(name, value);
        }
    }

    Ok(response)
}
