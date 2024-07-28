use crate::types::error::Error;

#[derive(Debug, PartialEq, Eq)]
pub enum 
ZeekProtocolType
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
impl std::str::FromStr for ZeekProtocolType
{
    type Err = Error;
    fn from_str(name: &str) -> Result<ZeekProtocolType, Error>
    {
        match name
        {
            "conn" => Ok(ZeekProtocolType::CONN),
            "dns" => Ok(ZeekProtocolType::DNS),
            "http" => Ok(ZeekProtocolType::HTTP),
            "files" => Ok(ZeekProtocolType::FILES),
            "ftp" => Ok(ZeekProtocolType::FTP),
            "ssl" => Ok(ZeekProtocolType::SSL),
            "x509" => Ok(ZeekProtocolType::X509),
            "smtp" => Ok(ZeekProtocolType::SMTP),
            "snmp" => Ok(ZeekProtocolType::SNMP),
            "ssh" => Ok(ZeekProtocolType::SSH),
            "pe" => Ok(ZeekProtocolType::PE),
            "dhcp" => Ok(ZeekProtocolType::DHCP),
            "ntp" => Ok(ZeekProtocolType::NTP),
            "smb" => Ok(ZeekProtocolType::SMB),
            "irc" => Ok(ZeekProtocolType::IRC),
            "rdp" => Ok(ZeekProtocolType::RDP),
            "ldap" => Ok(ZeekProtocolType::LDAP),
            "quic" => Ok(ZeekProtocolType::QUIC),
            "traceroute" => Ok(ZeekProtocolType::TRACEROUTE),
            "tunnel" => Ok(ZeekProtocolType::TUNNEL),
            "dpd" => Ok(ZeekProtocolType::DPD),
            "known" => Ok(ZeekProtocolType::KNOWN),
            "software" => Ok(ZeekProtocolType::SOFTWARE),
            "weird" => Ok(ZeekProtocolType::WEIRD),
            "notice" => Ok(ZeekProtocolType::NOTICE),
            "capture_loss" => Ok(ZeekProtocolType::CAPTURELOSS),
            "reporter" => Ok(ZeekProtocolType::REPORTER),
            "sip" => Ok(ZeekProtocolType::SIP),
            _ => Err(Error::ZeekProtocolTypeNotFound), // add error type instead of string
        }
    }
}
