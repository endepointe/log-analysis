//use crate::types::error::Error;
//use crate::types::log::LogType;
use crate::types::log_header::LogHeader;

//use std::str::FromStr;
//use std::fs::{self, File};
//use std::io::{self, Read};
//use std::path::Path;
use std::collections::HashMap;
//use std::collections::btree_map::BTreeMap;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug, PartialEq, Eq)]
pub struct 
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

