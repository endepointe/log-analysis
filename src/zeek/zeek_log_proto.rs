
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum 
ZeekProtocol
{
    NONE,
    CONN,
    DNS,
    HTTP,
    FILES,
    FTP,
    SSL,
    X509,
    SMTP,
    SNMP,
    SSH,
    PE,
    DHCP,
    NTP,
    SMB,
    IRC,
    RDP,
    LDAP,
    QUIC,
    TRACEROUTE,
    TUNNEL,
    DPD,
    KNOWN,
    SOFTWARE,
    WEIRD,
    NOTICE,
    CAPTURELOSS,
    REPORTER,
    SIP,
}
impl ZeekProtocol
{
    pub fn read(name: &str) -> ZeekProtocol
    {
        match name.to_ascii_lowercase().as_str()
        {
            "conn" => ZeekProtocol::CONN,
            "dns" => ZeekProtocol::DNS,
            "http" => ZeekProtocol::HTTP,
            "files" => ZeekProtocol::FILES,
            "ftp" => ZeekProtocol::FTP,
            "ssl" => ZeekProtocol::SSL,
            "x509" => ZeekProtocol::X509,
            "smtp" => ZeekProtocol::SMTP,
            "snmp" => ZeekProtocol::SNMP,
            "ssh" => ZeekProtocol::SSH,
            "pe" => ZeekProtocol::PE,
            "dhcp" => ZeekProtocol::DHCP,
            "ntp" => ZeekProtocol::NTP,
            "smb" => ZeekProtocol::SMB,
            "irc" => ZeekProtocol::IRC,
            "rdp" => ZeekProtocol::RDP,
            "ldap" => ZeekProtocol::LDAP,
            "quic" => ZeekProtocol::QUIC,
            "traceroute" => ZeekProtocol::TRACEROUTE,
            "tunnel" => ZeekProtocol::TUNNEL,
            "dpd" => ZeekProtocol::DPD,
            "known" => ZeekProtocol::KNOWN,
            "software" => ZeekProtocol::SOFTWARE,
            "weird" => ZeekProtocol::WEIRD,
            "notice" => ZeekProtocol::NOTICE,
            "capture_loss" => ZeekProtocol::CAPTURELOSS,
            "reporter" => ZeekProtocol::REPORTER,
            "sip" => ZeekProtocol::SIP,
            _ => ZeekProtocol::NONE, // add error type instead of string
        }
    }
    pub fn to_str(&self) -> &str 
    {
        match self {
            ZeekProtocol::CONN => "conn",
            ZeekProtocol::DNS => "dns",
            ZeekProtocol::HTTP => "http",
            ZeekProtocol::FILES => "files",
            ZeekProtocol::FTP => "ftp",
            ZeekProtocol::SSL => "ssl",
            ZeekProtocol::X509 => "x509",
            ZeekProtocol::SMTP => "smtp",
            ZeekProtocol::SNMP => "snmp",
            ZeekProtocol::SSH => "ssh",
            ZeekProtocol::PE => "pe",
            ZeekProtocol::DHCP => "dhcp",
            ZeekProtocol::NTP => "ntp",
            ZeekProtocol::SMB => "smb",
            ZeekProtocol::IRC => "irc",
            ZeekProtocol::RDP => "rdp",
            ZeekProtocol::LDAP => "ldap",
            ZeekProtocol::QUIC => "quic",
            ZeekProtocol::TRACEROUTE => "traceroute",
            ZeekProtocol::TUNNEL => "tunnel",
            ZeekProtocol::DPD => "dpd",
            ZeekProtocol::KNOWN => "known",
            ZeekProtocol::SOFTWARE => "software",
            ZeekProtocol::WEIRD => "weird",
            ZeekProtocol::NOTICE => "notice",
            ZeekProtocol::CAPTURELOSS => "capture_loss",
            ZeekProtocol::REPORTER => "reporter",
            ZeekProtocol::SIP => "sip",
            ZeekProtocol::NONE => "none", 
        }
    }
}
