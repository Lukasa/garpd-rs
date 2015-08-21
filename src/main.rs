extern crate libc;
extern crate errno;
use libc::{c_int, c_short, c_void, AF_PACKET};
use libc::{socket, recv, close};
use errno::errno;

static SOCK_RAW: c_int = 3;
static ETH_P_ARP: c_short = 0x0806;

fn main() {
    let sock = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ARP.to_be() as c_int) };
    if sock < 0 {
        println!("Failed to open socket: {}, {}", sock, errno());
        return
    }

    loop {
        let mut buf: [u8; 65535] = [0; 65535];
        let rc = unsafe { recv(sock, buf.as_mut_ptr() as *mut c_void, buf.len() as u64, 0) };
        if rc == 0 {
            println!("Zero length read!");
            break;
        }

        if rc < 14 {
            println!("Ethernet frame too short!");
            continue;
        }

        if ((buf[12] as i16) << 8) + (buf[13] as i16) != ETH_P_ARP {
            println!("Not arp packet");
            continue;
        }

        if rc < 43 {
            println!("ARP packet too short!");
            continue;
        }

        let sha = &buf[22 .. 28];
        let spa = &buf[28 .. 32];
        //let tha = &buf[32 .. 38];
        let tpa = &buf[38 .. 42];

        if spa != tpa {
            continue;
        }

        println!("Gratuitous ARP! IP: {}.{}.{}.{}, MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}", spa[0], spa[1], spa[2], spa[3], sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
    }

    unsafe { close(sock) };
}


#[test]
fn it_works() {
    basic();
}
