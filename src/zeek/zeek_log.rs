use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocol;

use std::str::FromStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough
fn print_type_of<T>(_: &T) {
    println!("Type: {}", std::any::type_name::<T>());
}

#[derive(Debug,Clone,PartialEq,Eq)]
struct 
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
    pub fn read(p : &std::path::Path, 
                data: &mut BTreeMap<ZeekProtocol, HashMap<String, Vec<String>>>) 
        -> Result<(), Error>
    {
        //dbg!(&p);
        dbg!(&data);
        let output = std::process::Command::new("zcat")
            .arg(&p)
            .output()
            .expect("failed to zcat the log file");
        let log_header = output.stdout;

        // todo: use self.header
        let mut separator : char = ' ';
        let mut set_separator = String::new();
        let mut empty_field = String::new();
        let mut unset_field = String::new();
        let mut path = String::new();
        let mut open = String::new();
        let mut fields = Vec::<String>::new(); //todo: (field_type_tuple)
        //let mut types = Vec::<String>::new();

        //let mut data = HashMap::new();

        match std::str::from_utf8(&log_header) 
        {
            Ok(v) => {
                // Load the header.
                let line: Vec<&str> = v.split('\n').collect();
                let result = line[0].split(' ')
                                .collect::<Vec<&str>>()[1]
                                .strip_prefix("\\x");

                // The return type needs to be a result to handle the None condition.

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
                set_separator = line[1].split(separator).collect::<Vec<_>>()[1].to_string();
                empty_field = line[2].split(separator).collect::<Vec<_>>()[1].to_string();
                unset_field = line[3].split(separator).collect::<Vec<_>>()[1].to_string();
                path = line[4].split(separator).collect::<Vec<_>>()[1].to_string();
                open = line[5].split(separator).collect::<Vec<_>>()[1].to_string();

                let s = line[6].split(separator).collect::<Vec<_>>();
                for i in 1..s.len() 
                {
                    fields.push(s[i].to_string());
                }


                if let Some(val) = data.get_mut(&ZeekProtocol::read(&path)) 
                {
                    // Load the data 
                    for n in 8..line.len() 
                    {
                        let row = &line[n].split(separator).collect::<Vec<_>>();
                        for m in 0..row.len() 
                        {
                            println!("field: {:?}, value: {:?}", &fields[m], &row[m]);   
                            let mut res = val.values_mut();
                            res.map(|r| r.insert(fields[m].to_string(), row[m].to_string()));
                        }
                    }
                    //for f in fields.iter() {
                    //    val.insert(f.to_string(), Vec::new());
                    //}
                }
                //let s = line[7].split(separator).collect::<Vec<_>>();
                //for i in 1..s.len() 
                //{
                //    types.push(s[i].to_string());
                //}
                //let p = p.to_str().expect("The path to log file should exist.")
                //    .split('/').collect::<Vec<_>>();
                //let p = &p[p.len()-1].split('.').collect::<Vec<_>>();
            }
            Err(e) => {
                return  Err(Error::Unspecified) 
            }
        }
        Ok(())
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
