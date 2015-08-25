extern crate errno;
extern crate libc;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate unix_socket;

use libc::{c_int, c_short, c_void, AF_PACKET};
use libc::{socket, recv, close};
use errno::errno;
use unix_socket::{UnixStream, UnixListener};

use std::io::prelude::*;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;

static SOCK_RAW: c_int = 3;
static ETH_P_ARP: c_short = 0x0806;

struct GARP {
    ip: [u8; 4],
    mac: [u8; 6],
}

fn listen_for_arps(arp_tx: Sender<GARP>) {
    let sock = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ARP.to_be() as c_int) };
    if sock < 0 {
        error!("Failed to open socket: {}, {}", sock, errno());
        return
    }

    loop {
        let mut buf: [u8; 65535] = [0; 65535];
        let rc = unsafe { recv(sock, buf.as_mut_ptr() as *mut c_void, buf.len() as u64, 0) };
        if rc == 0 {
            error!("Zero length socket read!");
            break;
        }

        if rc < 14 {
            info!("Ethernet frame too short!");
            continue;
        }

        if ((buf[12] as i16) << 8) + (buf[13] as i16) != ETH_P_ARP {
            info!("Not arp packet");
            continue;
        }

        if rc < 43 {
            info!("ARP packet too short!");
            continue;
        }

        let sha = &buf[22 .. 28];
        let spa = &buf[28 .. 32];
        //let tha = &buf[32 .. 38];
        let tpa = &buf[38 .. 42];

        if spa != tpa {
            continue;
        }

        let garp = GARP {
            ip: [spa[0], spa[1], spa[2], spa[3]],
            mac: [sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]],
        };

        arp_tx.send(garp).unwrap(); // Handle error.

    }

    unsafe { close(sock) };
}

fn report_garp(arp: GARP, unices: &mut Vec<UnixStream>) {
    let message = format!("{{\"ip\": \"{}.{}.{}.{}\", \"mac\": \"{:x}:{:x}:{:x}:{:x}:{:x}:{:x}\"}}\n", arp.ip[0], arp.ip[1], arp.ip[2], arp.ip[3], arp.mac[0], arp.mac[1], arp.mac[2], arp.mac[3], arp.mac[4], arp.mac[5]);

    for mut stream in unices {
        stream.write_all(message.as_bytes()).unwrap();
    }

    println!("Gratuitous ARP! IP: {}.{}.{}.{}, MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}", arp.ip[0], arp.ip[1], arp.ip[2], arp.ip[3], arp.mac[0], arp.mac[1], arp.mac[2], arp.mac[3], arp.mac[4], arp.mac[5]);
}

fn handle_new_connection(stream: UnixStream, unices: &mut Vec<UnixStream>) {
    unices.push(stream);
}

fn messenger(arp_rx: Receiver<GARP>, conn_rx: Receiver<UnixStream>) {
    let mut unices: Vec<UnixStream> = Vec::new();

    loop {
        select! {
            arp = arp_rx.recv() => {
                let arp = arp.unwrap();
                report_garp(arp, &mut unices);
            },
            stream = conn_rx.recv() => {
                let stream = stream.unwrap();
                handle_new_connection(stream, &mut unices);
            }
        }
    }
}


fn listen_for_connections(conn_tx: Sender<UnixStream>) {
    let listen = UnixListener::bind("/var/garpd").unwrap();

    for stream in listen.incoming() {
        match stream {
            Ok(stream) => {
                conn_tx.send(stream).unwrap();
            }
            Err(err) => {
                error!("Encounted error listening for Unix conns: {}", err);
                break;
            }
        }
    }
}

fn main() {
    env_logger::init().unwrap();
    info!("Launching garpd");

    // Spawn work threads.
    let (arp_tx, arp_rx) = channel();
    let (conn_tx, conn_rx) = channel();
    let x = thread::spawn(move || listen_for_arps(arp_tx));
    let y = thread::spawn(move || listen_for_connections(conn_tx));
    let z = thread::spawn(move || messenger(arp_rx, conn_rx));
    x.join().unwrap();
    y.join().unwrap();
    z.join().unwrap();
}


#[test]
fn it_works() {
    basic();
}
