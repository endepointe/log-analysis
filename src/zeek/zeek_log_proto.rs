use crate::types::error::Error;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
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
//impl std::str::FromStr for ZeekProtocol
impl ZeekProtocol
{
    pub fn read(name: &str) -> ZeekProtocol
    {
        match name
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
}
