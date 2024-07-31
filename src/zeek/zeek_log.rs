use crate::types::error::Error;
use crate::types::helpers::print_type_of;
use crate::zeek::zeek_log_proto::ZeekProtocol;

use std::str::FromStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;

#[derive(Debug,Clone,PartialEq,Eq)]
struct 
ZeekLogHeader
{
    pub separator: char,
    pub set_separator: String,
    pub empty_field: String,
    pub unset_field: String,
    pub path: String, 
    pub open: String,
    pub fields: Vec<String>,
    //pub types: Vec<String>,
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct 
ZeekLog
{
    //header: ZeekLogHeader,
    //pub data: HashMap<String, Vec<String>>, // make this a hashmap tomorrow
}
impl ZeekLog
{
    pub fn read(p : &std::path::Path, map: &mut HashMap::<String, Vec::<String>>)
        -> Result<(), Error>
    {
        let output = std::process::Command::new("zcat")
            .arg(&p)
            .output()
            .expect("failed to zcat the log file");
        let log_header = output.stdout;

        let mut separator : char = ' ';
        let mut fields = Vec::<String>::new(); 

        match std::str::from_utf8(&log_header) 
        {
            Ok(v) => {
                // Load the header.
                let line: Vec<&str> = v.split('\n').collect();
                let result = line[0].split(' ')
                                .collect::<Vec<&str>>()[1]
                                .strip_prefix("\\x");

                // File does not have header info.
                // This should not return an error due to the calling function's 
                // check. Leaving here until something useful is needed from the 
                // logs without a header.
                if result == None { 
                    return Err(Error::NoLogHeader) 
                } 

                let result = u8::from_str_radix(result.unwrap().trim(), 16)
                    .expect("Should have a separator character in the log file."); 

                separator = char::from(result);

                let s = line[6].split(separator).collect::<Vec<_>>();

                for i in 1..s.len() 
                {
                    fields.push(s[i].to_string());
                }

                let mut data = Vec::<String>::new();
                for f in fields.iter()
                {
                    map.insert(f.to_string(), Vec::<String>::new());
                    data.push(f.to_string());
                }

                // Should never fail.
                assert_eq!(data.len(), fields.len());

                // Load the data 
                for n in 8..line.len() // line.len() - 2 == #close\tdate which is not used.
                {
                    let items = line[n].split(separator).collect::<Vec<_>>();
                    if items[0] == "#close" {break;}
                    for item in 0..items.len() - 1
                    {
                        if let Some(m) = map.get_mut(&data[item])
                        {
                            m.push(items[item].to_string());
                        }
                    }
                }
            }
            Err(e) => {
                return  Err(Error::Unspecified) 
            }
        }
        Ok(())
    }
}
