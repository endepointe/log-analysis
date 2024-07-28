
#[derive(Debug, PartialEq, Eq)]
pub enum 
ProtocolType
{
    CONN,
    DNS,
    HTTP,
    FILES,
    FTP,
    SSL,
    X509,
    SMTP,
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
impl std::str::FromStr for ProtocolType
{
    type Err = String;
    fn from_str(name: &str) -> Result<ProtocolType, Self::Err>
    {
        match name
        {
            "conn" => Ok(ProtocolType::CONN),
            "dns" => Ok(ProtocolType::DNS),
            "http" => Ok(ProtocolType::HTTP),
            "files" => Ok(ProtocolType::FILES),
            "ftp" => Ok(ProtocolType::FTP),
            "ssl" => Ok(ProtocolType::SSL),
            "x509" => Ok(ProtocolType::X509),
            "smtp" => Ok(ProtocolType::SMTP),
            "ssh" => Ok(ProtocolType::SSH),
            "pe" => Ok(ProtocolType::PE),
            "dhcp" => Ok(ProtocolType::DHCP),
            "ntp" => Ok(ProtocolType::NTP),
            "smb" => Ok(ProtocolType::SMB),
            "irc" => Ok(ProtocolType::IRC),
            "rdp" => Ok(ProtocolType::RDP),
            "ldap" => Ok(ProtocolType::LDAP),
            "quic" => Ok(ProtocolType::QUIC),
            "traceroute" => Ok(ProtocolType::TRACEROUTE),
            "tunnel" => Ok(ProtocolType::TUNNEL),
            "dpd" => Ok(ProtocolType::DPD),
            "known" => Ok(ProtocolType::KNOWN),
            "software" => Ok(ProtocolType::SOFTWARE),
            "weird" => Ok(ProtocolType::WEIRD),
            "notice" => Ok(ProtocolType::NOTICE),
            "capture_loss" => Ok(ProtocolType::CAPTURELOSS),
            "reporter" => Ok(ProtocolType::REPORTER),
            "sip" => Ok(ProtocolType::SIP),
            _ => Err("ProtocolTypeNotFound".to_string()),
        }
    }
}
