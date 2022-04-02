use clap::{arg, Command};
use url::{Url, ParseError};
use std::io::{self, Read, Write, ErrorKind};
use std::net::{ToSocketAddrs, TcpStream};

use implementing_tls::base64::{self, Base64};

fn connect(url: &Url) -> io::Result<TcpStream> {
    let host_name = url.host_str().expect("Host required");
    let addrs = (host_name, url.port().unwrap_or(80)).to_socket_addrs()?;

    for addr in addrs {
        if let Ok(s) = TcpStream::connect(addr) {
            return Ok(s);
        }
    }

    Err(io::Error::new(ErrorKind::AddrNotAvailable, "Failed to resolve host address"))
}

fn response_string(stream: &mut TcpStream) -> io::Result<String> {
    let mut response = String::new();
    stream.read_to_string( &mut response)?;
    Ok(response)
}

fn proxy_auth(proxy_url: &Url) -> Option<Base64> {
    proxy_url.password().map(|pass| {
        let auth_str = format!("{}:{}", proxy_url.username(), pass);
        base64::encode(auth_str.as_bytes())
    })
}

fn via_proxy(proxy_url: &Url, request_url: &Url) -> io::Result<String> {
    println!("Requesting URL {} via proxy {}", request_url, proxy_url);

    let mut stream = connect(proxy_url)?;
    write!(stream, "GET {} HTTP/1.1\r\n", request_url)?;
    write!(stream, "Host: {}\r\n", request_url.host_str().unwrap_or(""))?;

    if let Some(auth) = proxy_auth(proxy_url) {
        write!(stream, "Proxy-Authorization: Basic {}\r\n", auth)?;
    }

    write!(stream, "Connection: close\r\n")?;

    write!(stream, "\r\n")?;
    stream.flush()?;

    response_string(&mut stream)
}

fn direct(request_url: &Url) -> io::Result<String> {
    let host_name = request_url.host_str().expect("Host required");
    println!("Requesting path {} from host {}", request_url.path(), host_name);

    let mut stream = connect(request_url)?;
    write!(stream, "GET {} HTTP/1.1\r\n", request_url.path())?;
    write!(stream, "Host: {}\r\n", host_name)?;
    write!(stream, "Connection: close\r\n")?;
    write!(stream, "\r\n")?;
    stream.flush()?;

    response_string(&mut stream)
}

pub fn main() {
    let matches = Command::new("http_client")
        .arg(arg!([url] "URL to GET").required(true))
        .arg(arg!(-p --proxy <URL> "URL of proxy to use").required(false))
        .get_matches();

    let url_str = matches.value_of("url").unwrap();
    let url = Url::parse(url_str).expect("Invalid URL");

    let response_result = match matches.value_of("proxy") {
        Some(proxy_url_str) => {
            let proxy_url = Url::parse(proxy_url_str).expect("Invalid proxy URL");
            via_proxy(&proxy_url, &url)
        },
        None => {
            direct(&url)
        }
    };

    match response_result {
        Ok(response) => {
            println!("{}", response);
        },
        Err(e) => {
            println!("Error executing request: {}", e);
        }
    }
}