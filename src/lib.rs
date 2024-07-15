// now learn how this all works
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;

#[derive(Debug,Copy,Clone)]
pub enum 
LogType
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
    CAPTURE_LOSS,
    REPORTER,
    SIP,
}
impl std::str::FromStr for LogType
{
    type Err = String;
    fn from_str(name: &str) -> Result<LogType, Self::Err>
    {
        match name
        {
            "conn" => Ok(LogType::CONN),
            "dns" => Ok(LogType::DNS),
            "http" => Ok(LogType::HTTP),
            "files" => Ok(LogType::FILES),
            "ftp" => Ok(LogType::FTP),
            "ssl" => Ok(LogType::SSL),
            "x509" => Ok(LogType::X509),
            "smtp" => Ok(LogType::SMTP),
            "ssh" => Ok(LogType::SSH),
            "pe" => Ok(LogType::PE),
            "dhcp" => Ok(LogType::DHCP),
            "ntp" => Ok(LogType::NTP),
            "smb" => Ok(LogType::SMB),
            "irc" => Ok(LogType::IRC),
            "rdp" => Ok(LogType::RDP),
            "ldap" => Ok(LogType::LDAP),
            "quic" => Ok(LogType::QUIC),
            "traceroute" => Ok(LogType::TRACEROUTE),
            "tunnel" => Ok(LogType::TUNNEL),
            "dpd" => Ok(LogType::DPD),
            "known" => Ok(LogType::KNOWN),
            "software" => Ok(LogType::SOFTWARE),
            "weird" => Ok(LogType::WEIRD),
            "notice" => Ok(LogType::NOTICE),
            "capture_loss" => Ok(LogType::CAPTURE_LOSS),
            "reporter" => Ok(LogType::REPORTER),
            "sip" => Ok(LogType::SIP),
            _ => Err("LogType not found".to_string()),
        }
    }
}


#[derive(Debug, Copy, Clone)]
pub struct
SearchParams<'a>
{
    pub log_type: Option<LogType>,
    pub ip: Option<&'a str>,
    pub time_range: Option<&'a str>, // todo
}
impl<'a> SearchParams<'a>
{
    pub fn new() -> Self
    {
        SearchParams {
            log_type: None,
            ip: None,
            time_range: None,
        }
    }
}

#[derive(Debug,Clone)]
pub struct LogHeader
{
    pub separator: char,
    pub set_separator: String,
    pub empty_field: String,
    pub unset_field: String,
    pub path: String, // could turn this into a list to store multiple dates
    pub open: String,
    // field and types may be better used as a tuple.
    // todo: (field_type_tuple)
    pub fields: Vec<String>,
    pub types: Vec<String>,
}
impl LogHeader
{
    pub fn new(p : &std::path::Path) -> Self
    {
        let output = std::process::Command::new("zcat")
            .arg(&p)
            .output()
            .expect("failed to zcat the log file");
        let log_header = output.stdout;

        let mut pos : u8 = 0;
        let mut separator : char = ' ';
        let mut set_separator = String::new();
        let mut empty_field = String::new();
        let mut unset_field = String::new();
        let mut path = String::new();
        let mut open = String::new();
        let mut fields = Vec::<String>::new(); //todo: (field_type_tuple)
        let mut types = Vec::<String>::new();

        match std::str::from_utf8(&log_header) 
        {
            Ok(v) => {
                let mut buffer = String::new();
                for c in v.chars() {
                    if c == '\n' { 
                        match pos 
                        {
                            0 => {
                                let result = buffer.split(' ')
                                                .collect::<Vec<&str>>()[1]
                                                .strip_prefix("\\x");
                                let result = u8::from_str_radix(result.unwrap(), 16)
                                    .expect("LOG_SEPARATER_CHAR: ");
                                separator = char::from(result);
                            }
                            1 => {
                                set_separator = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            2 => {
                                empty_field = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            3 => {
                                unset_field = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            4 => {
                                path = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            5 => {
                                open = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            6 => {
                                let s = buffer.split(separator).collect::<Vec<_>>();
                                for i in 1..s.len() 
                                {
                                    fields.push(s[i].to_string());
                                }
                            }
                            7 => {
                                let s = buffer.split(separator).collect::<Vec<_>>();
                                for i in 1..s.len() 
                                {
                                    types.push(s[i].to_string());
                                }
                            }
                            _ => {break;}
                        }
                        buffer.clear();
                        pos += 1; 
                        continue; // ignore the newline char.
                    } 
                    buffer.push(c);
                }
            }
            Err(e) => {
                eprintln!("{}",e.valid_up_to());
            }
        }

        LogHeader {
            separator,
            set_separator,
            empty_field,
            unset_field,
            path,
            open,
            fields,
            types,
        }
    }
    pub fn get_types(&self) -> &Vec<String>
    {
        &self.types
    }
    pub fn get_fields(&self) -> &Vec<String>
    {
        &self.fields
    }
}

#[derive(Debug)]
struct 
LogData<'a> 
{
    header: &'a LogHeader,
    data: HashMap<&'a str, Vec<&'a str>>,
}
impl<'a> LogData<'a>
{
    fn new(h: &'a LogHeader) -> Self
    {
        let fields = h.get_fields();
        let mut f = HashMap::<&'a str, Vec<&'a str>>::new();
        for field in fields
        {
            f.insert(&field, Vec::<&'a str>::new());
        }
        LogData {header: h, data: f}
    }
    fn add_field_entry(&mut self, key: &'a str, val: &'a str)
    {
        self.data.entry(key).or_insert(Vec::new()).push(val);
    }
}

#[derive(Debug)]
pub struct
LogDirectory<'a>
{
    day: &'a str,
    pub files: BTreeMap<String, LogData<'a>>,
}
impl<'a> LogDirectory<'a>
{
    pub fn new(p: &'a Path) -> Result<Self, &str>
    {
        // The default path of zeek logs on debian is /opt/zeek/logs.
        // The user is responsible for specifying a valid ancestor directory path to 
        // reach the path/to/your/logs/YYYY-MM-DD directories.
        match p.is_dir()
        {
            true => {
                let dir = p.to_str().unwrap();
                Ok(LogDirectory {
                    day: dir,
                    files: BTreeMap::new(),
                })
            }
            false => {
                Err("handle LogDirectory::new() error")
            }
        }
    }
    pub fn find(&mut self, params: SearchParams) -> std::io::Result<()> 
    {
        println!("{}:{} - Search Parameters: {:?}", file!(), line!(), params);
        for child in std::fs::read_dir(self.day)?
        {
            let child = child?;
            match child.file_name().into_string()
            {
                Ok(log) => {
                    let v = log.split('.').collect::<Vec<_>>();
                    println!("{}:{} -- {:?}",file!(),lne!(), v[0]); // at this point, read the 
                                                                     // create header, fill in data
                                                                     // and keep growing this. 
                                                                     // inserting typo so i know 
                                                                     // where to resume.
                }
                Err(e) => {continue;}
            }
        }
        Ok(())
    }
}

pub fn 
increment<'a>(val: &'a mut u32)
{
    *val += 1;
}

pub fn 
print_val<'a>(val: &'a u32)
{
    println!("print_val : val is {}",val);
}

