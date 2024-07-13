// now learn how this all works
use async_graphql::{Schema, Context, Object, 
    ComplexObject, SimpleObject, Request, Result, 
    EmptyMutation, EmptySubscription
};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use actix_web::{web, App, HttpServer, Responder};
use std::fs::File;
use std::io::{self, Read};
use flate2::read::GzDecoder;
use std::io::Write;
use std::sync::Mutex;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};


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
    pub fn set_header(p : &std::path::Path) -> Self 
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
pub struct LogData<'a> 
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

fn increment<'a>(val: &'a mut u32)
{
    *val += 1;
}

fn print_val<'a>(val: &'a u32)
{
    println!("print_val : val is {}",val);
}

mod tests 
{
    #[test]
    fn test_read_header()
    {
        use crate::LogHeader;
        // these values represent the input from the user.
        let date_dir = "zeek-test-logs/2024-07-02";
        let log_type = "conn";
        let start_time = "00:00:00";
        let end_time = "01:00:00";
        let log_gz = "log.gz";
        let header = format!("{}/{}.{}-{}.{}",date_dir, log_type, start_time, end_time, log_gz);
        let date_dir = std::path::Path::new(&header);
        let header = LogHeader::set_header(&date_dir);
        assert!(header.separator.is_whitespace());
        assert!(header.set_separator.len() > 0);
        assert!(header.empty_field.len() > 0);
        assert!(header.unset_field.len() > 0);
        assert!(header.path.len() > 0);
        assert!(header.open.len() > 0);
        assert!(header.fields.len() > 0);
        assert!(header.types.len() > 0);
        println!("{header:?}");
    }
    #[test]
    fn test_log_data()
    {
        use crate::LogData;
        use crate::LogHeader;
        let date_dir = "zeek-test-logs/2024-07-02";
        let log_type = "dns";
        let start_time = "00:00:00";
        let end_time = "01:00:00";
        let log_gz = "log.gz";
        let header = format!("{}/{}.{}-{}.{}",date_dir, log_type, start_time, end_time, log_gz);
        let date_dir = std::path::Path::new(&header);
        let h = LogHeader::set_header(&date_dir); 
        let mut log : LogData = LogData::new(&h);
        log.add_field_entry("test123","one");
        log.add_field_entry("test123","two");
        log.add_field_entry("test123","three");
        log.add_field_entry("test1","one");
        assert_eq!(log.data.get("test123").unwrap(), &vec!["one","two","three"]);
        println!("passed: {:?}",log.data.get("test123").unwrap());
        assert_eq!(log.data.get("test1").unwrap(), &vec!["one"]);
        println!("passed: {:?}",log.data.get("test1").unwrap());
    }

    #[test]
    fn test_lifetime()
    {
        use crate::increment;
        use crate::print_val;
        let mut x = 10; 
        print_val(&x);
        increment(&mut x);
        print_val(&x);
    }
}













