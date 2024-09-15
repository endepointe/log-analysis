use crate::types::error::Error;
use crate::types::types::LogTree;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_search_params::ZeekSearchParams;
use crate::types::helpers::print_type_of;

//#[cfg(feature = "ip2location")]
//use crate::ip2location::ip2location;

use crate::ip2location::{request,IP2LocationResponse};

use std::path::Path;
use std::io::{Read, Write, BufReader, BufRead};
use std::collections::{HashMap,HashSet};
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc,Mutex};
use std::thread;
use flate2::read::GzDecoder;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};


pub type TS = String; 
pub type UID = String;
pub type FUID = String;
pub type MD5 = String;
pub type SHA1 = String;
pub type SHA256 = String;
pub type BYTES = usize;
pub type FILETUPLE = (TS,UID,FUID,MD5,SHA1,SHA256,BYTES);

// Might be simpler to make these pub.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SummaryData
{
    ip_address: String,
    pub ip2location: Option<IP2LocationResponse>,
}
impl SummaryData
{
    pub fn new(ip_address: String) -> Self 
    {
        SummaryData {
            ip_address,
            ip2location: None,
        }
    }
    pub fn set_ip_address(&mut self, val: String){
        if self.ip_address.len() < 1 {
            self.ip_address = val;
        }
    }
    pub fn get_ip_address(&self) -> &String {&self.ip_address}
    pub fn set_ip2location_data(&mut self, val: Option<IP2LocationResponse>) {self.ip2location = val;}
    pub fn get_ip2location_data(&self) -> &Option<IP2LocationResponse> {&self.ip2location}
}

#[derive(Debug, PartialEq, Eq)]
pub struct
ZeekLog
{
    pub raw: LogTree,
    pub summary: HashMap<String, SummaryData>,
}
impl ZeekLog
{
    // Initializes structure to search through logs using the path_prefix/ as the
    // parent log directory.
    pub fn new() -> Self
    {
        ZeekLog {
            raw: BTreeMap::new(),
            summary: HashMap::<String, SummaryData>::new(),
        }
    }

    fn read(p : &std::path::Path, 
            map: &mut HashMap::<String, Vec::<String>>, 
            search_bits: u8,
            params: &ZeekSearchParams) -> Result<(), Error>
    {
        let mut _separator : char = ' ';
        let mut proto_type = Vec::<String>::new();
        let mut fields = Vec::<String>::new(); 
 
        let file = std::fs::File::open(p).expect("conn file should exist");

        let mut separator_set = false;
        let mut proto_type_set = false;
        let mut fields_set = false;
        let mut count: usize = 0;
        let mut s = String::new();
        let mut d = GzDecoder::new(file);
        let reader = BufReader::new(d);
        let mut header_line = 0;

        // maybe clean up the guard clauses...later. At the very least it would make the method
        // shorter. I would also get better at building with rust. 
        for line in reader.lines() 
        {
            if header_line > 7 {break;} 
            match header_line
            {
                0 => {
                    let separator_line = line.as_ref();
                    let result: Vec<&str> = separator_line
                        .expect("Should be able to read TSV file.")
                        .split(' ').collect::<Vec<&str>>();
                    if header_line == 0 && result[0] == "#separator"
                    {
                        separator_set = true;
                        let value = result[1].strip_prefix("\\x").expect("Should have a separator");
                        let value = u8::from_str_radix(value.trim(), 16)
                            .expect("Should have a separator character in the log file: "); 
                        _separator = char::from(value);
                    } 
                }
                4 => {
                    let proto_ref = line.as_ref();
                    let result: Vec<&str> = proto_ref.expect("proto_ref")
                        .split(_separator).collect::<Vec<&str>>();
                    if result[0] == "#path"
                    {
                        proto_type_set = true;
                        proto_type.push(result[1].to_string());
                    }
                }
                5 => {
                    //open
                }
                6 => {
                    let fields_ref = line.as_ref().expect("fields_ref")
                        .split(_separator).collect::<Vec<&str>>();
                    if fields_ref[0] == "#fields"
                    {
                        for i in 1..fields_ref.len() 
                        {
                            fields.push(fields_ref[i].to_string());
                        }
                        fields_set = true; // enables the data insertions
                    }
                    for f in fields.iter()
                    {
                        map.insert(f.to_string(), Vec::<String>::new());
                    }
                }
                7 => {
                    // types field. Leaving Skipping unless use case exists. 
                }
                _ => {
                    // do nothing.
                }
            }
            header_line = header_line + 1;
        }
        // reread, if the file is a TSV.
        let file = std::fs::File::open(p).expect("conn file should exist");
        let mut d = GzDecoder::new(file);
        let reader = BufReader::new(d);
        let mut header_line = 0;
        if separator_set 
        {
            for line in reader.lines() 
            {
                if header_line < 8 {
                    header_line = header_line + 1;
                    continue;
                } 

                let mut data: Vec<&str> = Vec::<&str>::new();

                if let Ok(content) = line.as_ref()
                {
                    if content.contains("#close") {break;}
                }
                data = line.as_ref().expect("values should be refd")
                    .split(_separator).collect::<Vec<&str>>();
                let mut iter = std::iter::zip(&fields,&data);
                for (field,item) in iter
                {
                    if let Some(fielditem) = map.get_mut(field)
                    {
                        fielditem.push(item.to_string());
                    }
                }
            }
        }
        Ok(())
    }

    // These searches should be the responsibility of the client
    // functions (TUI).
    // data (all)
    //fn _000(fields: &Vec<String>, 
    //        data: &Vec<&str>, 
    //        map: &mut HashMap<String, Vec<String>>) 
    //{
    //    let mut iter = std::iter::zip(fields,data);
    //    for (field,item) in iter
    //    {
    //        if let Some(fielditem) = map.get_mut(field)
    //        {
    //            fielditem.push(item.to_string());
    //        }
    //    }
    //}
    //// ip
    //fn _100(fields: &Vec<String>, 
    //        data: &Vec<&str>, 
    //        map: &mut HashMap<String, Vec<String>>, 
    //        params: &ZeekSearchParams) 
    //{

    //    let src_ip = params.src_ip.unwrap();
    //    let mut iter = std::iter::zip(fields,data);
    //    for (field,item) in iter
    //    {
    //        if let Some(mapkey) = map.get_mut(field)
    //        {
    //            if *item == src_ip
    //            {
    //                mapkey.push(item.to_string());
    //            }
    //        }
    //    }
    //}

    // ip + proto_type
    //fn _110(fields: &Vec<String>, 
    //        data: &Vec<&str>, 
    //        map: &mut HashMap<String, Vec<String>>, 
    //        params: &ZeekSearchParams,
    //        proto: ZeekProtocol) 
    //{        
    //    if let Some(t) = &params.proto_type
    //    {
    //        if ZeekProtocol::read(&t) == proto 
    //        {
    //            let src_ip = params.src_ip.unwrap();
    //            let mut iter = std::iter::zip(fields,data);
    //            for (field,item) in iter
    //            {
    //                if let Some(mapkey) = map.get_mut(field)
    //                {
    //                    if *item == src_ip
    //                    {
    //                        mapkey.push(item.to_string());
    //                    }
    //                }
    //            }
    //        }
    //    }
    //}
    ///////////////////////////////////////////////////////////

    fn _reduce(&mut self)
    {
        let mut keys_to_remove = Vec::new();
        for (outer_key, middle_map) in self.raw.iter_mut() 
        {
            let mut middle_keys_to_remove = Vec::new();
            for (middle_key, inner_map) in middle_map.iter_mut() 
            {
                let mut inner_keys_to_remove = Vec::new();
                for (inner_key, vec) in inner_map.iter_mut() 
                {
                    if vec.is_empty() 
                    {
                        inner_keys_to_remove.push(inner_key.clone());
                    }
                }
                for key in inner_keys_to_remove 
                {
                    inner_map.remove(&key);
                }
                if inner_map.is_empty() 
                {
                    middle_keys_to_remove.push(middle_key.clone());
                }
            }
            for key in middle_keys_to_remove 
            {
                middle_map.remove(&key);
            }
            if middle_map.is_empty() 
            {
                keys_to_remove.push(outer_key.clone());
            }
        }
        for key in keys_to_remove 
        {
            self.raw.remove(&key);
        }
    }
   
    // This should be returned as an overview for the analyst.
    fn _create_overview(&mut self)
    {
        let mut map: HashMap<String, SummaryData> = HashMap::new();

        for (proto, protovalue) in &self.raw
        {
            for (timefield, timevalue) in protovalue.iter()
            {
                // Maybe there is a better way to accomplish the following so... it 
                // may look a bit wierd here. In the inner hashmap, I need to get the 
                // timevalue (key,val) again to extract information from after creating the
                // Data struct. Maybe on another day I will be able to look at it from a 
                // different angle to make this mor efficient. Until then, this is where 
                // we are at.
                for (field,value) in timevalue.iter()
                {
                    if field == "id.orig_h"
                    {
                        let src_ip = &value[0].to_string();
                        if !map.contains_key(src_ip)
                        {
                            self.summary.insert(src_ip.to_string(), SummaryData::new(src_ip.to_string()));
                        } 
                        //let d: &mut SummaryData = self.summary.get_mut(src_ip).unwrap();
                        
                        // Add SummaryData as dev progresses.
                    }
                }
            }
        }
    }

    pub fn search(&mut self, params: &ZeekSearchParams) -> Result<(), Error> 
    {
        let search : u8 = params.check();
        let path = params.get_selected_date_path();     
        let path = Path::new(path.as_str());     
        if !path.is_dir() {
            return Err(Error::SearchInvalidStartDate)
        }
        for entry in std::fs::read_dir(&path).expect("error reading path") 
        {
            let log = entry.unwrap();
            let p = log.path();
            let p = p.to_str().expect("The path to log file should exist.");
            let p = p.split('/').collect::<Vec<_>>();
            let p = p[p.len()-1].split('.').collect::<Vec<_>>();

            //////////////////////////////////////////////////////
            // NOTE: p[0] = proto, p[1] = time, p[2..] = filetype
            //////////////////////////////////////////////////////
            let proto = ZeekProtocol::read(p[0]);

            if !self.raw.contains_key(&proto) && !(proto == ZeekProtocol::NONE)
            {
                // To handle post processing easier, convert the inner
                // vector to a hashmap and return it. 
                let mut hp = HashMap::<String, HashMap<String, Vec<String>>>::new();
                hp.insert(p[1].to_string(), HashMap::<String, Vec::<String>>::new());
                self.raw.insert(proto.clone(), hp);
            }

            // Create time range (e.g. 00-01) and use as keys to BTreeMap.
            if let Some(value) = self.raw.get_mut(&proto) 
            {
                value.insert(p[1].to_string(), HashMap::<String, Vec::<String>>::new());
            }

            // Only pass the vector corresponding to the proto.
            if let Some(t) = self.raw.get_mut(&proto) 
            {
                if let Some(g) = t.get_mut(&p[1].to_string())
                {
                    // thread here?
                    ////////////////////////////////////////
                    let _ = Self::read(log.path().as_path(), g, search, params);
                }
            }
        }

        Self::_reduce(self);
        //dbg!(&self.raw);
        Self::_create_overview(self);

        if cfg!(feature = "ip2location") 
        {
            let mut count = 0;
            let arc_data = Arc::new(Mutex::new(self.summary.clone()));
            let mut handles = Vec::<thread::JoinHandle<()>>::new();

            for (ip,val) in arc_data.lock().unwrap().iter_mut()
            {
                //////////////////////////////////////////////////////////////////////
                //dbg!("Consider setting up the ip2loc.json file to save api queries.");
                //dbg!("Otherwise, this will work with live data, jsut omit the ip2location feature and the LOCAL_JSON_DB environment variable.");
                //std::process::exit(1);
                //////////////////////

                let ip_key = ip.clone();
                let arc_data_clone = Arc::clone(&arc_data);

                let handle = thread::spawn(move || {
                    let mut arc_ip2locresponse = Arc::new(Mutex::new(IP2LocationResponse::new()));
                    {
                        let mut bound_arc_data = arc_data_clone.lock().unwrap();
                        if let Some(entry) = bound_arc_data.get_mut(&ip_key)
                        {
                            let ip_addr = request(&entry.get_ip_address());
                            if let Ok(addr) = ip_addr
                            {
                                let mut locked_ip2locresponse = arc_ip2locresponse.lock().unwrap();
                                let addr = addr.as_str();
                                let addr = addr.replace(' ',"");
                                locked_ip2locresponse.create(&addr);
                                let res_clone = locked_ip2locresponse.clone();
                                entry.set_ip2location_data(Some(res_clone));
                            }
                        }
                    }
                });
                handles.push(handle);
            }
            for handle in handles
            {
                handle.join();
            }
            self.summary = Arc::try_unwrap(arc_data).unwrap().into_inner().unwrap();
        } 

        return Ok(())
    }

}

