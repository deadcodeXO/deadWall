use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, TransportSlice};

#[derive(Clone, Copy, Debug, Default)]
pub struct Volume {
    pub rx: u64,
    pub tx: u64,
}

impl Volume {
    pub fn add(&mut self, bytes: u32, outbound: bool) {
        if outbound {
            self.tx += u64::from(bytes);
        } else {
            self.rx += u64::from(bytes);
        }
    }

    pub fn total(self) -> u64 {
        self.rx + self.tx
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Flow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: u8,
}

impl Flow {
    pub fn kind(self) -> &'static str {
        match (self.protocol, self.remote.port(), self.local.port()) {
            (6 | 17, 53, _) | (6 | 17, _, 53) => "DNS",
            (6, 443, _) | (6, _, 443) => "HTTPS port",
            (17, 443, _) | (17, _, 443) => "QUIC port",
            (6, 80, _) | (6, _, 80) => "HTTP port",
            (6, _, _) => "TCP",
            (17, _, _) => "UDP",
            (1 | 58, _, _) => "ICMP",
            _ => "Other IP",
        }
    }
}

fn packet(data: &[u8], link: i32) -> Option<LaxSlicedPacket<'_>> {
    Some(match link {
        1 => LaxSlicedPacket::from_ethernet(data).ok()?,
        113 => {
            let kind = u16::from_be_bytes(data.get(14..16)?.try_into().ok()?);
            LaxSlicedPacket::from_ether_type(EtherType(kind), data.get(16..)?)
        }
        276 => {
            let kind = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
            LaxSlicedPacket::from_ether_type(EtherType(kind), data.get(20..)?)
        }
        0 | 108 => LaxSlicedPacket::from_ip(data.get(4..)?).ok()?,
        12 | 101 => LaxSlicedPacket::from_ip(data).ok()?,
        _ => return None,
    })
}

pub fn arp_claim(data: &[u8], link: i32) -> Option<(std::net::Ipv4Addr, [u8; 6])> {
    // The Ethernet discriminator avoids a second parse for ordinary IP frames.
    if link != 1
        || !matches!(
            u16::from_be_bytes(data.get(12..14)?.try_into().ok()?),
            0x0806 | 0x8100 | 0x88a8 | 0x9100
        )
    {
        return None;
    }
    let LaxNetSlice::Arp(arp) = packet(data, link)?.net? else {
        return None;
    };
    if arp.hw_addr_type().0 != 1
        || arp.proto_addr_type().0 != 0x0800
        || !matches!(arp.operation().0, 1 | 2)
    {
        return None;
    }
    let bytes: [u8; 4] = arp.sender_protocol_addr().try_into().ok()?;
    let ip = std::net::Ipv4Addr::from(bytes);
    let mac: [u8; 6] = arp.sender_hw_addr().try_into().ok()?;
    if ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || mac == [0; 6]
        || mac[0] & 1 != 0
    {
        return None;
    }
    Some((ip, mac))
}
pub fn classify(data: &[u8], link: i32, local: &HashSet<IpAddr>) -> Option<(Flow, bool)> {
    let packet = packet(data, link)?;
    let (source, dest) = match packet.net.as_ref()? {
        LaxNetSlice::Ipv4(ip) => (
            IpAddr::V4(ip.header().source_addr()),
            IpAddr::V4(ip.header().destination_addr()),
        ),
        LaxNetSlice::Ipv6(ip) => (
            IpAddr::V6(ip.header().source_addr()),
            IpAddr::V6(ip.header().destination_addr()),
        ),
        _ => return None,
    };
    let protocol = packet.ip_payload()?.ip_number.0;
    let (sport, dport) = match packet.transport {
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port()),
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port()),
        _ => (0, 0),
    };
    let outbound = local.contains(&source);
    if !outbound
        && !local.contains(&dest)
        && !dest.is_multicast()
        && !matches!(dest, IpAddr::V4(addr) if addr.is_broadcast())
    {
        return None;
    }
    let source = SocketAddr::new(source, sport);
    let dest = SocketAddr::new(dest, dport);
    let (local, remote) = if outbound {
        (source, dest)
    } else {
        (dest, source)
    };
    Some((
        Flow {
            local,
            remote,
            protocol,
        },
        outbound,
    ))
}

#[derive(Default)]
pub struct Flows {
    pub volume: Volume,
    pub rows: HashMap<Flow, Volume>,
    pub other: Volume,
}

impl Flows {
    pub fn observe(&mut self, flow: Flow, bytes: u32, outbound: bool) {
        self.volume.add(bytes, outbound);
        if let Some(volume) = self.rows.get_mut(&flow) {
            volume.add(bytes, outbound);
        } else if self.rows.len() < 1024 {
            let mut volume = Volume::default();
            volume.add(bytes, outbound);
            self.rows.insert(flow, volume);
        } else {
            self.other.add(bytes, outbound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_both_directions_with_a_truncated_payload() {
        let packet =
            etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [1, 1, 1, 1], 64).udp(50000, 53);
        let mut bytes = Vec::new();
        packet.write(&mut bytes, &[0; 200]).unwrap();
        let (flow, outbound) = classify(
            &bytes[..40],
            12,
            &HashSet::from(["10.0.0.1".parse().unwrap()]),
        )
        .unwrap();
        assert!(outbound);
        assert_eq!(flow.remote, "1.1.1.1:53".parse().unwrap());
        assert_eq!(flow.kind(), "DNS");
        let (flow, outbound) =
            classify(&bytes, 12, &HashSet::from(["1.1.1.1".parse().unwrap()])).unwrap();
        assert!(!outbound);
        assert_eq!(flow.remote, "10.0.0.1:50000".parse().unwrap());
        assert!(classify(&bytes, 12, &HashSet::new()).is_none());
    }
}
