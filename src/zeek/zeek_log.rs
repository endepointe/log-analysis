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


type TS = String; 
type UID = String;
type FUID = String;
type MD5 = String;
type SHA1 = String;
type SHA256 = String;
type BYTES = usize;
type FILETUPLE = (TS,UID,FUID,MD5,SHA1,SHA256,BYTES);

fn _get_ip_db() -> Vec<String>
{
    let mut file = std::fs::File::open("ip.db").expect("ip.db should exist already.");
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).expect("should be able to read ip.db");
    let mut v = Vec::<String>::new();
    let content: Vec<_> = buffer.split('\n').collect();
    for line in content
    {
        v.push(line.to_string())
    }
    v
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Data
{
    ip_address: String,
    frequency: usize,
    connection_uids: Vec<UID>,
    protocols: Vec<String>,
    time_ranges: HashMap<String, u32>,
    file_info: Vec<HashMap<String,String>>,
    conn_state: Vec::<String>,
    history: Vec::<String>,
    dports: Vec<u16>,
    ip2location: Option<IP2LocationResponse>,
    malicious: bool, // virustotal?
    bytes_transferred: u64,
    related_ips: Vec<String>,
}
impl Data
{
    pub fn new(ip_address: String) -> Self 
    {
        Data {
            ip_address,
            frequency: 0,
            connection_uids: Vec::<UID>::new(),
            protocols: Vec::<String>::new(),
            time_ranges: HashMap::<String, u32>::new(),
            file_info: Vec::<HashMap::<String,String>>::new(),
            conn_state: Vec::<String>::new(),
            history: Vec::<String>::new(),
            dports: Vec::<u16>::new(),
            ip2location: None,
            malicious: true,
            bytes_transferred: 0,
            related_ips: Vec::<String>::new(),
        }
    }
    pub fn get_ip_address(&self) -> &String
    {
        &self.ip_address
    }
    fn _increment_frequency(&mut self) 
    {
        self.frequency = self.frequency + 1;
    }
    pub fn get_frequency(&self) -> usize
    {
        self.frequency
    }
    pub fn set_ip2location_data(&mut self, val: Option<IP2LocationResponse>)
    {
        self.ip2location = val;
    }
    pub fn get_ip2location_data(&self) -> &Option<IP2LocationResponse>
    {
        &self.ip2location
    }
    fn set_protocol(&mut self, val: String)
    {
        if !self.protocols.contains(&val)
        {
            self.protocols.push(val);
        }
    }
    pub fn get_protocols(&self) -> &Vec<String>
    {
        &self.protocols
    }
    fn set_connection_uid(&mut self, val: UID)
    {
        if !self.connection_uids.contains(&val)
        {
            self.connection_uids.push(val);
        }
    }
    pub fn get_connection_uids(&self) -> &Vec<String> { &self.connection_uids }

    fn set_file_info(&mut self, t: TS, u: UID, f: FUID, m: MD5, s1: SHA1, s2: SHA256, b: BYTES)
    {
        let mut map = HashMap::<String,String>::new();
        map.insert("ts".to_string(), t.to_string());
        map.insert("uid".to_string(), u.to_string());
        map.insert("fuid".to_string(), f.to_string());
        map.insert("md5".to_string(), m.to_string());
        map.insert("sha1".to_string(), s1.to_string());
        map.insert("sha256".to_string(), s2.to_string());
        map.insert("total_size".to_string(), b.to_string());
        self.file_info.push(map);
    }
    pub fn get_file_info(&self) -> &Vec::<HashMap::<String,String>> { &self.file_info }

    fn set_time_range(&mut self, val: String)
    {
        if let Some(time) = self.time_ranges.get_mut(&val)
        {
            *time = *time + 1;
        } else 
        {
            self.time_ranges.insert(val, 1);
        }
        self._increment_frequency();
        assert_eq!(&self.time_ranges.len() <= &self.frequency, true);
    }
    fn set_conn_state(&mut self, val: String)
    {
        if !self.conn_state.contains(&val) 
        {
            self.conn_state.push(val);
        }
    }
    pub fn get_conn_state(&self) -> &Vec<String>
    {
        &self.conn_state
    }
    fn set_history(&mut self, val: String)
    {
        if !self.history.contains(&val) 
        {
            self.history.push(val);
        }
    }
    pub fn get_history(&self) -> &Vec<String>
    {
        &self.history
    }
    fn set_dport(&mut self, val: u16)
    {
        self.dports.push(val);
    }
    pub fn get_dports(&self) -> &Vec<u16>
    {
        &self.dports
    }
    fn increment_bytes_transferred(&mut self, val: u64) 
    {
        self.bytes_transferred = self.bytes_transferred + val;
    }
    pub fn get_bytes_transferred(&self) -> u64
    {
        self.bytes_transferred
    }
    fn set_related_ip(&mut self, val: String)
    {
        todo!();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct
ZeekLog
{
    _raw: LogTree,
    pub data: HashMap<String, Data>,
}
impl ZeekLog
{
    // Initializes structure to search through logs using the path_prefix/ as the
    // parent log directory.
    pub fn new() -> Self
    {
        ZeekLog {
            _raw: BTreeMap::new(),
            data: HashMap::<String, Data>::new(),
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
                8 => {
                    let mut data: Vec<&str> = Vec::<&str>::new();
                    data = line.as_ref().expect("values should be refd")
                        .split(_separator).collect::<Vec<&str>>();
                    // Load the data based on search_bits
                    match search_bits
                    {
                        0 => {Self::_000(&fields, &data, map);}
                        4 => {Self::_100(&fields, &data, map, params);}
                        6 => {
                            Self::_110(&fields, &data, map, params, 
                                       ZeekProtocol::read(proto_type[0].as_str()));
                        }
                        _ => {}
                    }
                    header_line = 0;
                }
                _ => {
                    // Most likely reading the rest of the log file or
                    // it is not a TSV formatted file.
                    // Do nothing.
                }
            }
            header_line = header_line + 1;
        }
        Ok(())
    }

    // data (all)
    fn _000(fields: &Vec<String>, 
            data: &Vec<&str>, 
            map: &mut HashMap<String, Vec<String>>) 
    {
        let mut iter = std::iter::zip(fields,data);
        for (field,item) in iter
        {
            if let Some(fielditem) = map.get_mut(field)
            {
                fielditem.push(item.to_string());
            }
        }
    }
    // ip
    fn _100(fields: &Vec<String>, 
            data: &Vec<&str>, 
            map: &mut HashMap<String, Vec<String>>, 
            params: &ZeekSearchParams) 
    {

        let src_ip = params.src_ip.unwrap();
        let mut iter = std::iter::zip(fields,data);
        for (field,item) in iter
        {
            if let Some(mapkey) = map.get_mut(field)
            {
                if *item == src_ip
                {
                    mapkey.push(item.to_string());
                }
            }
        }
    }

    // ip + proto_type
    fn _110(fields: &Vec<String>, 
            data: &Vec<&str>, 
            map: &mut HashMap<String, Vec<String>>, 
            params: &ZeekSearchParams,
            proto: ZeekProtocol) 
    {        
        if let Some(t) = &params.proto_type
        {
            if ZeekProtocol::read(&t) == proto 
            {
                let src_ip = params.src_ip.unwrap();
                let mut iter = std::iter::zip(fields,data);
                for (field,item) in iter
                {
                    if let Some(mapkey) = map.get_mut(field)
                    {
                        if *item == src_ip
                        {
                            mapkey.push(item.to_string());
                        }
                    }
                }
            }
        }
    }
    
    fn _reduce(&mut self)
    {
        let mut keys_to_remove = Vec::new();
        for (outer_key, middle_map) in self._raw.iter_mut() 
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
            self._raw.remove(&key);
        }
    }
   
    // This should be returned as an overview for the analyst.
    fn _create_overview(&mut self)
    {
        let arc_raw = Arc::new(Mutex::new(&self._raw));
        let mut map: HashMap<String, Data> = HashMap::new();
        let mut handles = Vec::<thread::JoinHandle<()>>::new();

        for (proto, protovalue) in &self._raw
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
                            self.data.insert(src_ip.to_string(), Data::new(src_ip.to_string()));
                            let handle = std::thread::spawn(move || {

                            });
                        } 
                        let d: &mut Data = self.data.get_mut(src_ip).unwrap();
                        d.set_protocol(proto.to_str().to_string());
                        d.set_time_range(timefield.to_string());
                        for (key,val) in timevalue.iter() 
                        {
                            if key == "uid" && val[0] != "-"
                            {
                                d.set_connection_uid(val[0].to_string());
                            }
                            if key == "fuid" && val[0] != "-"
                            {
                                d.set_file_info(timevalue.get("ts").unwrap()[0].to_string(),
                                     timevalue.get("uid").unwrap()[0].to_string(),
                                     timevalue.get("fuid").unwrap()[0].to_string(),
                                     timevalue.get("md5").unwrap()[0].to_string(),
                                     timevalue.get("sha1").unwrap()[0].to_string(),
                                     timevalue.get("sha256").unwrap()[0].to_string(),
                                     timevalue.get("total_bytes").unwrap()[0].parse::<usize>().unwrap());
                            }

                            if key == "orig_bytes" && val[0] != "-"
                            {
                                d.increment_bytes_transferred(val[0].parse::<u64>()
                                                              .expect("should be a parsable string"));
                                d.set_conn_state(timevalue.get("conn_state").unwrap()[0].to_string());
                                d.set_history(timevalue.get("history").unwrap()[0].to_string());
                            }
                            if proto.to_str() == "conn"
                            {
                                d.set_conn_state(timevalue.get("conn_state").unwrap()[0].to_string());
                                d.set_history(timevalue.get("history").unwrap()[0].to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    //TODO: threading 
    //fn _create_data(&mut self) 
    //{
    //    let data_map = Arc::new(Mutex::new(&self._raw));
    //    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    //    let results = Arc::new(Mutex::new(Vec::<Data>::new()));
    //    for data in data_map.lock().unwrap().iter()
    //    {
    //    }
    //    //for handle in handles
    //    //{
    //    //    handle.join().unwrap();
    //    //}
    //}

    pub fn search(&mut self, params: &ZeekSearchParams) -> Result<(), Error> 
    {
        let search : u8 = params.check();
        let path = params.get_start_date_path();     
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

            if !self._raw.contains_key(&proto) && !(proto == ZeekProtocol::NONE)
            {
                // To handle post processing easier, convert the inner
                // vector to a hashmap and return it. 
                let mut hp = HashMap::<String, HashMap<String, Vec<String>>>::new();
                hp.insert(p[1].to_string(), HashMap::<String, Vec::<String>>::new());
                self._raw.insert(proto.clone(), hp);
            }

            // Create time range (e.g. 00-01) and use as keys to BTreeMap.
            if let Some(value) = self._raw.get_mut(&proto) 
            {
                value.insert(p[1].to_string(), HashMap::<String, Vec::<String>>::new());
            }

            // Only pass the vector corresponding to the proto.
            if let Some(t) = self._raw.get_mut(&proto) 
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
        Self::_create_overview(self);

        if cfg!(feature = "ip2location") 
        {
            let mut count = 0;
            let arc_data = Arc::new(Mutex::new(self.data.clone()));
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
            self.data = Arc::try_unwrap(arc_data).unwrap().into_inner().unwrap();
        } 

        return Ok(())
    }

}

