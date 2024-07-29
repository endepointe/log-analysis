use crate::types::error::Error;

#[derive(Debug, PartialEq, Eq)]
pub enum 
ZeekProtocol
{
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
impl std::str::FromStr for ZeekProtocol
{
    type Err = Error;
    fn from_str(name: &str) -> Result<ZeekProtocol, Error>
    {
        match name
        {
            "conn" => Ok(ZeekProtocol::CONN),
            "dns" => Ok(ZeekProtocol::DNS),
            "http" => Ok(ZeekProtocol::HTTP),
            "files" => Ok(ZeekProtocol::FILES),
            "ftp" => Ok(ZeekProtocol::FTP),
            "ssl" => Ok(ZeekProtocol::SSL),
            "x509" => Ok(ZeekProtocol::X509),
            "smtp" => Ok(ZeekProtocol::SMTP),
            "snmp" => Ok(ZeekProtocol::SNMP),
            "ssh" => Ok(ZeekProtocol::SSH),
            "pe" => Ok(ZeekProtocol::PE),
            "dhcp" => Ok(ZeekProtocol::DHCP),
            "ntp" => Ok(ZeekProtocol::NTP),
            "smb" => Ok(ZeekProtocol::SMB),
            "irc" => Ok(ZeekProtocol::IRC),
            "rdp" => Ok(ZeekProtocol::RDP),
            "ldap" => Ok(ZeekProtocol::LDAP),
            "quic" => Ok(ZeekProtocol::QUIC),
            "traceroute" => Ok(ZeekProtocol::TRACEROUTE),
            "tunnel" => Ok(ZeekProtocol::TUNNEL),
            "dpd" => Ok(ZeekProtocol::DPD),
            "known" => Ok(ZeekProtocol::KNOWN),
            "software" => Ok(ZeekProtocol::SOFTWARE),
            "weird" => Ok(ZeekProtocol::WEIRD),
            "notice" => Ok(ZeekProtocol::NOTICE),
            "capture_loss" => Ok(ZeekProtocol::CAPTURELOSS),
            "reporter" => Ok(ZeekProtocol::REPORTER),
            "sip" => Ok(ZeekProtocol::SIP),
            _ => Err(Error::ZeekProtocolNotFound), // add error type instead of string
        }
    }
}
