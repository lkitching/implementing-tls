use clap::{arg, Command};
use url::{Url, ParseError};
use std::io::{Read, Write};
use std::net::{ToSocketAddrs, TcpStream};

pub fn main() {
    let matches = Command::new("http_client")
        .arg(arg!([url] "URL to GET").required(true))
        .get_matches();

    let url_str = matches.value_of("url").unwrap();
    let url = Url::parse(url_str).expect("Invalid URL");
    let host_name = url.host_str().expect("Host required");

    println!("Requesting path {} from host {}", url.path(), host_name);

    for addrs in (host_name, url.port().unwrap_or(80)).to_socket_addrs() {
        for addr in addrs {
            let mut stream = TcpStream::connect(addr).expect("Failed to connect");
            write!(stream, "GET {} HTTP/1.1\r\n", url.path()).expect("Failed to write version line");
            write!(stream, "Host: {}\r\n", host_name).expect("Failed to write host header");
            write!(stream, "Connection: close\r\n").expect("Failed to write connection header");
            write!(stream, "\r\n").expect("Failed to write terminating newlines");
            stream.flush();

            // TODO: read response
            let mut response = String::new();
            stream.read_to_string( &mut response).expect("Error reading response");
            println!("{}", response);

            break;
        }

    }
}