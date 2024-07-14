// now learn how this all works
use std::fs::{self, File};
use std::io::{self, Read};

#[derive(Debug,Clone)]
pub struct LogHeader
{
    pub separator: char,
    pub set_separator: String,
    pub empty_field: String,
    pub unset_field: String,
    pub path: String, // could turn this into a list to store multiple dates
    pub open: String,
    pub fields: Vec<String>,
    pub types: Vec<String>,
}
impl LogHeader
{
    pub fn set_header(p : &std::path::Path) -> Self  // this should be a static method
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
        let mut fields = Vec::<String>::new();
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
                                let result = buffer.split(' ').collect::<Vec<&str>>()[1].strip_prefix("\\x");
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
pub struct 
LogData<'a> 
{
    pub header: &'a LogHeader,
    pub data: std::collections::HashMap<&'a str, Vec<&'a str>>,
}
impl<'a> LogData<'a>
{
    pub fn new(h: &'a LogHeader) -> Self
    {
        let fields = h.get_fields();
        let mut f = std::collections::HashMap::<&'a str, Vec<&'a str>>::new();
        for field in fields
        {
            f.insert(&field, Vec::<&'a str>::new());
        }
        LogData {header: h, data: f}
    }
    pub fn add_field_entry(&mut self, key: &'a str, val: &'a str)
    {
        self.data.entry(key).or_insert(Vec::new()).push(val);
    }
}



#[derive(Debug)]
pub struct
Search<'a>
{
    pub ip: Option<&'a str>,
    pub time_range: Option<&'a str>, // todo
}
impl<'a> Search<'a>
{
    pub fn new() -> Self
    {
        Search {ip: None, time_range: None}
    }
    // This method requires that the zeek log parent path is known.
    pub fn ip_addr(&'a self, ip: &'a str) -> std::io::Result<&str> //Result<&str, &str>
    {
        let existing_log_dir = std::path::Path::new("zeek-test-logs/2024-07-02");
        assert_eq!(existing_log_dir.is_dir(), true);
        for d in fs::read_dir(&existing_log_dir)?
        {
            println!("{:?}", d?.path());
        }
        Ok(ip)
    }
    pub fn test(&self, ip: std::net::IpAddr)
    {
        println!("test: {ip:?}");
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

