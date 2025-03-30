use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);

pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn http_get(url: &str) -> anyhow::Result<HttpResponse> {
    let url = url::Url::parse(url)?;
    let scheme = url.scheme();
    if scheme != "http" {
        anyhow::bail!("only http:// is supported (not https://)");
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let addr = (host, port).to_socket_addrs()?.next().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;

    stream.set_read_timeout(Some(TIMEOUT))?;

    let path = if let Some(q) = url.query() {
        format!("{}?{}", url.path(), q)
    } else {
        url.path().to_string()
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );

    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let parsed = parse_http_response(&response)?;

    // redirects
    if (300..400).contains(&parsed.status_code) {
        if let Some(location) = parsed
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
        {
            return http_get(&location);
        } else {
            anyhow::bail!(
                "redirect (HTTP {}) without Location header",
                parsed.status_code
            );
        }
    }

    Ok(parsed)
}

fn parse_http_response(response: &[u8]) -> anyhow::Result<HttpResponse> {
    let split_at = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response: no header-body split"))?;

    let (header_bytes, body) = response.split_at(split_at + 4);
    let headers_str = std::str::from_utf8(header_bytes)?;

    let mut lines = headers_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing status line"))?;

    let status_code = status_line
        .split_whitespace()
        .nth(1) // status code is the second word
        .ok_or_else(|| anyhow::anyhow!("missing status code"))?
        .parse::<u16>()?;

    let mut parsed_headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(": ") {
            parsed_headers.push((k.to_string(), v.to_string()));
        }
    }

    Ok(HttpResponse {
        status_code,
        headers: parsed_headers,
        body: body.to_vec(),
    })
}
