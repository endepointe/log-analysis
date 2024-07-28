use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocolType;
use crate::zeek::zeek_log_header::ZeekLogHeader;
use crate::zeek::zeek_log_data::ZeekLogData;
use crate::zeek::zeek_log_directory::ZeekLogDirectory;

use std::str::FromStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug, PartialEq, Eq)]
pub struct
ZeekSearchParams<'a>
{
    pub start_date: Option<&'a str>,
    pub end_date: Option<&'a str>,
    pub log_type: Option<ZeekProtocolType>,
    pub ip: Option<&'a str>,
}
impl<'a> ZeekSearchParams<'a>
{
    pub fn new() -> Self 
    {
        ZeekSearchParams {
            start_date: None,
            end_date: None,
            log_type: None,
            ip: None,
        }
    }
    pub fn set_start_date(&mut self, start: &'a Path) -> Result<(), Error>
    {
        match Self::check_date_format(start)
        {
            true => {
                self.start_date = Some(start.to_str().unwrap()); 
                Ok(())
            }
            false => {
                Err(Error::SearchInvalidStartDate)
            }
        }
    }

    // todo: check that the chars in range between [0-9]. 
    // For now, [Aa-Zz] passes and it shouldn't.
    fn check_date_format(p: &'a Path) -> bool
    {
        // The default path of zeek logs on debian is /opt/zeek/logs.
        // The user is responsible for specifying a valid directory path to 
        // reach the path/to/zeek/logs/YYYY-MM-DD directories.
        // The expected format is the format yyyy-mm-dd.

        let val = &p.to_str();
        if let Some(v) = val 
        {
            let v : Vec<_> = v.split('/').collect();
            let v : Vec<_> = v[v.len()-1].split('-').collect();
            if v.len() != 3 
            {
                return false
            }
            for i in 0..v.len() 
            {
                let number = u16::from_str(v[i]);
                if let Err(e) = number 
                {
                    return false
                }
            }
            return true 
        } 
        false
    }
}
