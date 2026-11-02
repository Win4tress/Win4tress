//! HTTPS requests through WinHTTP (the system's TLS and proxy settings), for
//! the threat lists (SPEC §11 "Suspicious host contacted") and reputation
//! lookups (SPEC §12).

use std::ffi::c_void;
use std::time::Duration;

use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_ETAG,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts,
};
use windows::core::{HSTRING, PCWSTR, w};

/// Closes a WinHTTP handle when dropped.
struct Handle(*mut c_void);

// SAFETY: WinHTTP handles may be used from any thread, and the handle is only
// closed once, on drop.
unsafe impl Send for Handle {}
// SAFETY: as above; WinHTTP serialises use of a handle internally.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a handle WinHTTP returned and nothing else closes.
            let _ = unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

/// "https://host/path?query" → (host, "/path?query"). Only HTTPS.
fn split(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://")?;
    match rest.find('/') {
        Some(i) => Some((&rest[..i], &rest[i..])),
        None => Some((rest, "/")),
    }
}

/// An answer, whatever its status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u32,
    pub body: Vec<u8>,
    /// The ETag header, to ask with If-None-Match next time (304 = unchanged).
    pub etag: Option<String>,
}

/// Header lines as WinHTTP wants them: "Name: value\r\n…", UTF-16.
fn header_block(headers: &[(&str, &str)]) -> Vec<u16> {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>()
        .encode_utf16()
        .collect()
}

/// A session to one HTTPS host whose connection is kept between requests
/// (DNS over HTTPS): WinHTTP pools it. Dropping the session closes it.
pub struct Session {
    // Field order: the connection closes before its session.
    connection: Handle,
    _session: Handle,
    host: String,
}

impl Session {
    pub fn open(host: &str, timeout: Duration) -> Result<Session, String> {
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: handles opened here are owned by `Handle`s and closed once.
        unsafe {
            let session = Handle(WinHttpOpen(
                w!("win4tress"),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            ));
            if session.0.is_null() {
                return Err("WinHTTP isn't available".into());
            }
            let _ = WinHttpSetTimeouts(session.0, ms, ms, ms, ms);
            let connection = Handle(WinHttpConnect(session.0, &HSTRING::from(host), 443, 0));
            if connection.0.is_null() {
                return Err(format!("can't reach {host}"));
            }
            Ok(Session {
                connection,
                _session: session,
                host: host.to_string(),
            })
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// A request on the kept connection; `path` starts with `/`.
    pub fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        max_bytes: usize,
    ) -> Result<Response, String> {
        // SAFETY: the connection handle lives as long as `self`.
        unsafe {
            send_on(
                &self.connection,
                &self.host,
                method,
                path,
                headers,
                body,
                max_bytes,
            )
        }
    }
}

/// An HTTPS request with extra headers and an optional body; at most
/// `max_bytes` of answer. An error says what failed; any HTTP status is an
/// answer.
pub fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Response, String> {
    let (host, path) = split(url).ok_or("only https:// addresses")?;
    let session = Session::open(host, timeout)?;
    session.send(method, path, headers, body, max_bytes)
}

/// One request on an open connection.
///
/// # Safety
/// `connection` must be a live WinHttpConnect handle.
unsafe fn send_on(
    connection: &Handle,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    max_bytes: usize,
) -> Result<Response, String> {
    let body = body.unwrap_or(&[]);
    let length = u32::try_from(body.len()).map_err(|_| "the body is too large")?;
    let headers = header_block(headers);
    // SAFETY: the request handle is opened here and closed by `Handle`;
    // buffers outlive the calls that use them; the connection is live (the
    // caller's contract).
    unsafe {
        let request = Handle(WinHttpOpenRequest(
            connection.0,
            &HSTRING::from(method),
            &HSTRING::from(path),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return Err("can't make the request".into());
        }
        WinHttpSendRequest(
            request.0,
            (!headers.is_empty()).then_some(headers.as_slice()),
            (!body.is_empty()).then_some(body.as_ptr().cast()),
            length,
            length,
            0,
        )
        .map_err(|e| format!("sending the request to {host}: {e}"))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut())
            .map_err(|e| format!("no answer from {host}: {e}"))?;
        let mut status = 0u32;
        let mut size = size_of::<u32>() as u32;
        let mut index = 0u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some((&raw mut status).cast()),
            &mut size,
            &mut index,
        )
        .map_err(|e| format!("reading the answer's status: {e}"))?;
        let mut etag_buf = [0u16; 256];
        let mut etag_size = (etag_buf.len() * 2) as u32;
        let mut etag_index = 0u32;
        let etag = WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_ETAG,
            PCWSTR::null(),
            Some(etag_buf.as_mut_ptr().cast()),
            &mut etag_size,
            &mut etag_index,
        )
        .ok()
        .map(|()| String::from_utf16_lossy(&etag_buf[..(etag_size / 2) as usize]))
        .filter(|e| !e.is_empty());
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let mut read = 0u32;
            WinHttpReadData(
                request.0,
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &mut read,
            )
            .map_err(|e| format!("reading the answer: {e}"))?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read as usize]);
            if body.len() > max_bytes {
                return Err(format!("larger than {max_bytes} bytes"));
            }
        }
        Ok(Response { status, body, etag })
    }
}

/// Downloads `url` (HTTPS), at most `max_bytes`. Anything but 200 is an
/// error, e.g. "HTTP 401".
pub fn get(url: &str, max_bytes: usize, timeout: Duration) -> Result<Vec<u8>, String> {
    let r = request("GET", url, &[], None, max_bytes, timeout)?;
    if r.status != 200 {
        return Err(format!("HTTP {}", r.status));
    }
    Ok(r.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_host_and_path() {
        assert_eq!(
            split("https://example.com/a/b?c"),
            Some(("example.com", "/a/b?c"))
        );
        assert_eq!(split("https://example.com"), Some(("example.com", "/")));
        assert_eq!(split("http://example.com/"), None);
    }

    #[test]
    fn headers_are_one_crlf_block() {
        let block = header_block(&[("x-apikey", "k"), ("Accept", "application/json")]);
        assert_eq!(
            String::from_utf16(&block).unwrap(),
            "x-apikey: k\r\nAccept: application/json\r\n"
        );
        assert!(header_block(&[]).is_empty());
    }
}
