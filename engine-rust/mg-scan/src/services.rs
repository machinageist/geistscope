// Author: Jeff
// Date: 2026-05-01
// Description: Maps well-known port numbers to IANA service names

// Map port number to service name
pub fn service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        194 => "irc",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        515 => "printer",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 => "docker",
        2376 => "docker-tls",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        6443 => "kubernetes",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        9300 => "elasticsearch-cluster",
        9418 => "git",
        10250 => "kubelet",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(80), "http");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(3306), "mysql");
        assert_eq!(service_name(27017), "mongodb");
    }

    #[test]
    fn unknown_port() {
        assert_eq!(service_name(9999), "unknown");
    }

    #[test]
    fn dhcp_both_ports() {
        assert_eq!(service_name(67), "dhcp");
        assert_eq!(service_name(68), "dhcp");
    }
}
