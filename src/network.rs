use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub country: String,
    pub as_number: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacketDirection {
    Incoming,
    Outgoing,
    Internal,
    External,
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    // pub timestamp: Instant,
    pub size: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub service_info: Option<ServiceInfo>,
    pub direction: PacketDirection,
}

#[derive(Debug)]
pub struct BasicStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub incoming_packets: u64,
    pub outgoing_packets: u64,
}

impl BasicStats {
    pub fn new() -> Self {
        BasicStats {
            total_packets: 0,
            total_bytes: 0,
            incoming_packets: 0,
            outgoing_packets: 0,
        }
    }

    pub fn update(&mut self, packet: &NetworkPacket) {
        self.total_packets += 1;
        self.total_bytes += packet.size as u64;

        match packet.direction {
            PacketDirection::Incoming => self.incoming_packets += 1,
            PacketDirection::Outgoing => self.outgoing_packets += 1,
            _ => {}
        }
    }
}

struct IpRange {
    start_ip: u32,
    end_ip: u32,
    as_number: String,
    country_code: String,
    as_description: String,
}

pub struct NetworkMonitor {
    ip_ranges: Vec<IpRange>,
    pub stats: BasicStats,
}

impl NetworkMonitor {
    pub fn new(path: &str) -> Self {
        let file = File::open(path).expect("Failed to open IP database file");
        let reader = BufReader::new(file);
        let mut ip_ranges = Vec::new();

        for line in reader.lines() {
            if let Ok(line) = line {
                if line.starts_with("#") || line.trim().is_empty() {
                    continue;
                }

                let fields: Vec<&str> = line.split('\t').collect();

                if fields.len() >= 5 {
                    if let (Ok(start_ip), Ok(end_ip)) =
                        (fields[0].parse::<Ipv4Addr>(), fields[1].parse::<Ipv4Addr>())
                    {
                        let start_ip_num = u32::from(start_ip);
                        let end_ip_num = u32::from(end_ip);

                        ip_ranges.push(IpRange {
                            start_ip: start_ip_num,
                            end_ip: end_ip_num,
                            as_number: fields[2].to_string(),
                            country_code: fields[3].to_string(),
                            as_description: fields[4].to_string(),
                        });
                    }
                }
            }
        }

        NetworkMonitor {
            ip_ranges,
            stats: BasicStats::new(),
        }
    }

    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Option<ServiceInfo> {
        let ip_num = u32::from(ip);

        for range in &self.ip_ranges {
            if ip_num >= range.start_ip && ip_num <= range.end_ip {
                return Some(ServiceInfo {
                    name: range.as_description.clone(),
                    country: range.country_code.clone(),
                    as_number: range.as_number.clone(),
                });
            }
        }

        None
    }

    pub fn is_private_ip(&self, ip: Ipv4Addr) -> bool {
        ip.is_private()
    }

    pub fn process_packet(
        &mut self,
        ip_packet: &pnet::packet::ipv4::Ipv4Packet,
        protocol: String,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> NetworkPacket {
        let src_ip = ip_packet.get_source();
        let dst_ip = ip_packet.get_destination();
        let size = ip_packet.get_total_length();

        let direction = if self.is_private_ip(dst_ip) && !self.is_private_ip(src_ip) {
            PacketDirection::Incoming
        } else if self.is_private_ip(src_ip) && !self.is_private_ip(dst_ip) {
            PacketDirection::Outgoing
        } else if self.is_private_ip(src_ip) && self.is_private_ip(dst_ip) {
            PacketDirection::Internal
        } else {
            PacketDirection::External
        };

        let service_info = match direction {
            PacketDirection::Incoming => self.lookup_ip(src_ip),
            PacketDirection::Outgoing => self.lookup_ip(dst_ip),
            _ => None,
        };

        let packet = NetworkPacket {
            // timestamp: Instant::now(),
            size,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            service_info,
            direction,
        };

        self.stats.update(&packet);

        packet
    }
}
