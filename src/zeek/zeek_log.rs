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
    header: ZeekLogHeader,
    //pub data: HashMap<String, Vec<String>>, // make this a hashmap tomorrow
}
impl ZeekLog
{
    pub fn read(p : &std::path::Path, time: String,
                data: &mut Vec::<Vec::<String>>)
                //data: &mut HashMap::<String, Vec::<String>>) // See notes in
                //zeek_log_directory.rs (line 150ish)
        -> Result<(), Error>
    {
        let output = std::process::Command::new("zcat")
            .arg(&p)
            .output()
            .expect("failed to zcat the log file");
        let log_header = output.stdout;

        let mut separator : char = ' ';
        //let mut set_separator = String::new();
        //let mut empty_field = String::new();
        //let mut unset_field = String::new();
        //let mut path = String::new();
        //let mut open = String::new();
        let mut fields = Vec::<String>::new(); 
        //let mut types = Vec::<String>::new(); // match types with a map? 

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
                //set_separator = line[1].split(separator).collect::<Vec<_>>()[1].to_string();
                //empty_field = line[2].split(separator).collect::<Vec<_>>()[1].to_string();
                //unset_field = line[3].split(separator).collect::<Vec<_>>()[1].to_string();
                //path = line[4].split(separator).collect::<Vec<_>>()[1].to_string();
                //open = line[5].split(separator).collect::<Vec<_>>()[1].to_string();

                let s = line[6].split(separator).collect::<Vec<_>>();

                for i in 1..s.len() 
                {
                    fields.push(s[i].to_string());
                }
                for f in fields.iter()
                {
                    //data.insert(f.to_string(), Vec::<String>::new());
                    let mut v = Vec::<String>::new();
                    v.push(f.to_string());
                    data.push(v);
                }

                // Load the data 
                for n in 8..line.len() // line.len() - 2 == #close\tdate which is not used.
                {
                    let items = line[n].split(separator).collect::<Vec<_>>();
                    if items[0] == "#close" {break;}
                    for item in 0..items.len() - 1
                    {
                        data[item].push(items[item].to_string());
                    }
                }
            }
            Err(e) => {
                return  Err(Error::Unspecified) 
            }
        }
        Ok(())
        // Determine if it is useful to return the header.
        //Ok(ZeekLog {
        //    header: ZeekLogHeader {
        //        separator,
        //        set_separator,
        //        empty_field,
        //        unset_field,
        //        path,
        //        open,
        //        fields,
        //        //types,
        //    },
        //    //data
        //})
    }
}
