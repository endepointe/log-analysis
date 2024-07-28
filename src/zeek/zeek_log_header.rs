use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocolType;

use std::str::FromStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct 
ZeekLogHeader
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
impl ZeekLogHeader
{
    pub fn read(p : &std::path::Path) -> Self
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

                                if result == None { continue; } // File does not have header info.
                                                                // This file may have relevant
                                                                // information. Unsure how to
                                                                // handle it at this time.
                                let result = u8::from_str_radix(result.unwrap().trim(), 16)
                                    .expect("LOG_SEPARATER_CHAR: "); // add error to types. 
                                                                     // do better.
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

        ZeekLogHeader {
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

