mod network;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use network::{NetworkMonitor, PacketDirection};

fn main() {
    let interface_names_match = |iface: &NetworkInterface| iface.name == "en0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let mut network_monitor = NetworkMonitor::new("./ip2asn-combined.tsv");

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                if packet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip_packet) = Ipv4Packet::new(packet.payload()) {
                        let (protocol, src_port, dst_port) =
                            match ip_packet.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                                        (
                                            "TCP".to_string(),
                                            Some(tcp.get_source()),
                                            Some(tcp.get_destination()),
                                        )
                                    } else {
                                        ("TCP".to_string(), None, None)
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                                        (
                                            "UDP".to_string(),
                                            Some(udp.get_source()),
                                            Some(udp.get_destination()),
                                        )
                                    } else {
                                        ("UDP".to_string(), None, None)
                                    }
                                }
                                other => (format!("{:?}", other), None, None),
                            };

                        let network_packet = network_monitor
                            .process_packet(&ip_packet, protocol, src_port, dst_port);

                        match network_packet.direction {
                            PacketDirection::Incoming => {
                                if let Some(info) = &network_packet.service_info {
                                    println!(
                                        "INCOMING FROM: {} ({}), Size: {} bytes, Protocol: {}, Ports: {:?} → {:?}",
                                        info.name,
                                        info.country,
                                        network_packet.size,
                                        network_packet.protocol,
                                        network_packet.src_port,
                                        network_packet.dst_port
                                    );
                                }
                            }
                            PacketDirection::Outgoing => {
                                if let Some(info) = &network_packet.service_info {
                                    println!(
                                        "OUTGOING TO: {} ({}), Size: {} bytes, Protocol: {}, Ports: {:?} → {:?}",
                                        info.name,
                                        info.country,
                                        network_packet.size,
                                        network_packet.protocol,
                                        network_packet.src_port,
                                        network_packet.dst_port
                                    );
                                }
                            }
                            _ => {}
                        }

                        if network_monitor.stats.total_packets % 100 == 0 {
                            println!("\n--- BASIC STATS ---");
                            println!("Total Packets: {}", network_monitor.stats.total_packets);
                            println!("Total Bytes: {}", network_monitor.stats.total_bytes);
                            println!(
                                "Incoming Packets: {}",
                                network_monitor.stats.incoming_packets
                            );
                            println!(
                                "Outgoing Packets: {}",
                                network_monitor.stats.outgoing_packets
                            );
                            println!("------------------\n");
                        }
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
