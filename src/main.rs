use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use serde_json::Value;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

// 定義 sql_logs 結構體
#[derive(Debug)]
struct SqlLog {
    conn_hash: String,
    stmt_id: u32,
    exec_id: u32,
    exec_time: u128,
    sql_type: String,
    exe_status: String,
    db_ip: IpAddr,
    client_ip: IpAddr,
    sql_stmt: String,
    stmt_bind_vars: Option<Value>,
}

// 計算 hash
fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

// 判斷 SQL 類型
fn determine_sql_type(uri: &str) -> String {
    if uri.contains("_search") {
        "SELECT".to_string()
    } else if uri.contains("_update") || uri.contains("_doc") {
        "UPDATE".to_string()
    } else if uri.contains("_delete") {
        "DELETE".to_string()
    } else if uri.contains("_bulk") {
        "BULK".to_string()
    } else {
        "UNKNOWN".to_string()
    }
}

fn print_tcp_info(tcp_packet: &TcpPacket, ip_packet: &Ipv4Packet) {
    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
        println!(
            "IP Packet: {}:{} -> {}:{}",
            ip_packet.get_source(),
            tcp_packet.get_source(),
            ip_packet.get_destination(),
            tcp_packet.get_destination()
        );
        println!("TCP Packet flags: {:?}", tcp_packet.get_flags());
        let transmission_protocol = if tcp_packet.get_flags() & 0x02 != 0 {
            "SYN"
        } else if tcp_packet.get_flags() & 0x10 != 0 {
            "ACK"
        } else if tcp_packet.get_flags() & 0x01 != 0 {
            "FIN"
        } else if tcp_packet.get_flags() & 0x04 != 0 {
            "RST"
        } else {
            "UNKNOWN"
        };

        let application_protocol = if tcp_packet.get_destination() == 9200 || tcp_packet.get_source() == 9200 {
            "Elasticsearch"
        } else {
            "UNKNOWN"
        };

        println!("Transmission Protocol: {}", transmission_protocol);
        println!("Application Protocol: {}", application_protocol);
    }
}

fn main() {
    // 選擇網路介面
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == "tap0") // 修改成你的網卡名稱
        .expect("Network interface not found");

    // 抓取封包
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    let mut stmt_id = 1;
    let mut exec_id = 1;

    while let Ok(packet) = rx.next() {
        let eth_packet = EthernetPacket::new(packet).unwrap();

        // 過濾 IPv4 封包
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            // 過濾 TCP 封包
            if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {

                    let DEBUG = std::env::var("DEBUG").unwrap_or_else(|_| "N".to_string()) ;
                    if DEBUG == "Y" {
                        print_tcp_info(&tcp_packet, &ip_packet);
                    }

                    // 假設 Elasticsearch 使用 9200 埠
                    if tcp_packet.get_destination() == 9200 || tcp_packet.get_source() == 9200 {
                        println!("-----Elasticsearch Packet-----");
                        let payload = tcp_packet.payload();
                        if let Ok(payload_str) = str::from_utf8(payload) {
                            // 嘗試解析 JSON 數據
                            if let Ok(json_data) = serde_json::from_str::<Value>(payload_str) {
                                // 提取 SQL 日誌所需的欄位
                                let sql_stmt = payload_str.to_string();
                                println!("payload str: {:?}", sql_stmt);
                                let sql_type = determine_sql_type(&sql_stmt);
                                let exe_status = if tcp_packet.get_flags() & 0x10 != 0 {
                                    "SUCCESS".to_string()
                                } else {
                                    "FAILURE".to_string()
                                };
                                let conn_hash = calculate_hash(&sql_stmt).to_string();
                                let exec_time = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis();

                                // 建立 SqlLog 物件
                                let sql_log = SqlLog {
                                    conn_hash,
                                    stmt_id,
                                    exec_id,
                                    exec_time,
                                    sql_type,
                                    exe_status,
                                    db_ip: IpAddr::V4(ip_packet.get_destination()),
                                    client_ip: IpAddr::V4(ip_packet.get_source()),
                                    sql_stmt,
                                    stmt_bind_vars: Some(json_data),
                                };

                                // 列印日誌
                                println!("{:?}", sql_log);

                                // 更新 ID
                                exec_id += 1;
                            }
                        }
                    }
                }
            }
        }
    }
}
