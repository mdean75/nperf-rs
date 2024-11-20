use mio::net::{TcpListener, TcpStream, UdpSocket};
use socket2::{Domain, Protocol, SockRef, Socket, Type};

use crate::{test::Stream, test::TestState};
use std::io::Error;
use std::io::{self, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket as AsRawFd;
use std::time::Duration;

pub fn gettime() -> String {
    // return Local::now().format("%Y-%m-%d %H:%M:%S.%6f").to_string();
    String::new()
}

pub fn write_socket(mut stream: &TcpStream, mut buf: &[u8], add_header: bool) -> io::Result<usize> {
    println!("write_socket: {:?}", buf);
    let mut temp_buf = vec![];
    if add_header {
        // let mut temp_buf = vec![];
        temp_buf.append((buf.len() as u16).to_be_bytes().to_vec().as_mut());
        temp_buf.extend_from_slice(buf);

        // buf = temp_buf.as_slice();
    }
    println!("write_socket, what is tmp_buf: {:?}", temp_buf.as_slice());
    match stream.write(temp_buf.as_slice()) {
        Ok(n) => {
            println!("write_socket: sent {} bytes", n);
            return Ok(n);
        }
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            println!("write_socket: would block");
            return Ok(0);
        }
        Err(e) => {
            println!("Write error {}", e);
            return Err(e.into());
        }
    }
}

pub fn drain_message<T: Stream + 'static>(stream: &mut T) -> io::Result<String> {
    println!("Draining message");
    let mut buf = String::new();
    loop {
        let mut data = [0; 8192];
        match stream.read(&mut data) {
            Ok(0) => {
                return Err(Error::last_os_error());
            }
            Ok(n) => {
                println!("Read {} bytes: {:?}", n, data[0..n].to_vec());
                buf += String::from_utf8(data[0..n].to_vec()).unwrap().as_str();
            }
            Err(ref e) => {
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(buf),
                    _ => return Err(Error::last_os_error()),
                };
            }
        }
    }
}

pub fn drain_message_with_header<T: Stream + 'static>(stream: &mut T) -> io::Result<String> {
    println!("Draining message with header");
    let mut buf = String::new();
    loop {
        let mut header_bytes = [0;2];
        match stream.read(&mut header_bytes) {
            Ok(0) => {
                return Err(Error::last_os_error());
            }
            Ok(n) => {
                // we have the header, now determine how many bytes we need to read
                let bytes_to_read = u16::from_be_bytes(header_bytes);
                // let mut data = Vec::with_capacity(bytes_to_read as usize);
                let mut data = vec![0; bytes_to_read as usize];

                match stream.read(&mut data) {
                    Ok(0) => {
                        return Err(Error::last_os_error());
                    }
                    Ok(n) => {
                        buf += String::from_utf8(data[0..n].to_vec()).unwrap().as_str();
                    }
                    Err(ref e) => {
                        match e.kind() {
                            io::ErrorKind::Interrupted => continue,
                            io::ErrorKind::WouldBlock => return Ok(buf),
                            _ => return Err(Error::last_os_error()),
                        };
                    }
                }
            }
            Err(ref e) => {
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(buf),
                    _ => return Err(Error::last_os_error()),
                }
            }
        }
        // let mut data = [0; 8192];
        // match stream.read(&mut data) {
        //     Ok(0) => {
        //         return Err(Error::last_os_error());
        //     }
        //     Ok(n) => {
        //         buf += String::from_utf8(data[0..n].to_vec()).unwrap().as_str();
        //     }
        //     Err(ref e) => {
        //         match e.kind() {
        //             io::ErrorKind::Interrupted => continue,
        //             io::ErrorKind::WouldBlock => return Ok(buf),
        //             _ => return Err(Error::last_os_error()),
        //         };
        //     }
        // }
    }
}

pub fn send_state(stream: &TcpStream, state: TestState, add_header: bool) {
    println!("Sending state {:?}", state);
    let byte: &mut [u8] = &mut [state as u8];
    write_socket(&stream, byte, add_header).unwrap();
}

pub fn make_cookie() -> String {
    let rndchars: String = String::from("abcdefghijklmnopqrstuvwxyz234567");
    return rndchars;
}
/*
void make_cookie(const char *cookie) {
    unsigned char *out = (unsigned char *)cookie;
    size_t pos;
    static const unsigned char rndchars[] = "abcdefghijklmnopqrstuvwxyz234567";

    readentropy(out, COOKIE_SIZE);
    for (pos = 0; pos < (COOKIE_SIZE - 1); pos++) {
      out[pos] = rndchars[out[pos] % (sizeof(rndchars) - 1)];
    }
    out[pos] = '\0';
  }

*/
pub fn set_nonblocking(stream: &TcpStream, nonblocking: bool) {
    let sck = SockRef::from(stream);
    match sck.set_nonblocking(nonblocking) {
        Ok(_) => return,
        Err(e) => {
            println!("Failed to set nonblocking {}", e.to_string());
            return;
        }
    }
}

pub fn set_nodelay<T: Stream + AsRawFd + 'static>(stream: &T) {
    let sck = SockRef::from(stream);
    match sck.set_nodelay(true) {
        Ok(_) => return,
        Err(e) => {
            println!("Failed to set nodelay {}", e.to_string());
            return;
        }
    }
}
pub fn set_linger<T: Stream + AsRawFd + 'static>(stream: &T) {
    let sck = SockRef::from(stream);
   //  match sck.set_linger(Some(Duration::from_secs(1))) {
    match sck.set_linger(Some(Duration::from_secs(1))) {
        Ok(_) => return,
        Err(e) => {
            println!("Failed to set nodelay {}", e.to_string());
            return;
        }
    }
}
pub fn _set_send_buffer_size<T: Stream + AsRawFd + 'static>(stream: &T, sz: usize) {
    let sck = SockRef::from(stream);
    match sck.set_send_buffer_size(sz) {
        Ok(_) => return,
        Err(e) => {
            println!("Failed to set send buffer size {}", e.to_string());
            return;
        }
    }
}
pub fn _set_recv_buffer_size<T: Stream + AsRawFd + 'static>(stream: &T, sz: usize) {
    let sck = SockRef::from(stream);
    match sck.set_recv_buffer_size(sz) {
        Ok(_) => return,
        Err(e) => {
            println!("Failed to set recv buffer size {}", e.to_string());
            return;
        }
    }
}
pub fn set_mss_listener(stream: &TcpListener, mss: u32) -> io::Result<()> {
    let sck = SockRef::from(stream);
    #[cfg(unix)]
    {
        match sck.set_mss(mss) {
            Ok(_) => Ok(()),
            Err(e) => {
                println!("Failed to set mss {}", mss);
                return Err(e);
            }
        }
    }
    #[cfg(windows)]
    Ok(())
}

pub fn create_net_udp_socket(addr: SocketAddr) -> std::net::UdpSocket {
    let sck = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP)).unwrap();
    sck.set_reuse_address(true).unwrap();
    sck.set_recv_buffer_size(212992).unwrap();
    sck.set_send_buffer_size(212992).unwrap();
    sck.set_nonblocking(true).unwrap();
    sck.bind(&addr.into()).unwrap();
    std::net::UdpSocket::from(sck)
}
pub fn create_mio_udp_socket(addr: SocketAddr) -> UdpSocket {
    UdpSocket::from_std(create_net_udp_socket(addr))
}
