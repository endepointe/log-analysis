use crate::types::error::Error;
use crate::types::types::LogTree;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_search_params::ZeekSearchParams;
use crate::types::helpers::print_type_of;
use std::path::Path;
use std::io::{Read, Write, BufReader, BufRead};
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;
use flate2::read::GzDecoder;
use serde::{Serialize, Deserialize};


#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct
ZeekLog
{
    pub data: LogTree,
}
impl ZeekLog
{
    // Initializes structure to search through logs using the path_prefix/ as the
    // parent log directory.
    //pub fn new(p: Option<&'a Path>) -> Self //Result<Self, Error>
    pub fn new() -> Self
    {
        ZeekLog {
            data: BTreeMap::new()
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

        // maybe clean up the guard clauses...later. At the very least it would make the method
        // shorter. I would also get better at building with rust. 
        for line in reader.lines() 
        {
            if !separator_set 
            {
                let separator_line = line.as_ref();
                let result: Vec<&str> = separator_line
                    .expect("Should have been able to read the line.")
                    .split(' ').collect::<Vec<&str>>();

                if result[0] == "#separator"
                {
                    separator_set = true;
                    let value = result[1].strip_prefix("\\x").expect("Should have a separator");
                    let value = u8::from_str_radix(value.trim(), 16)
                        .expect("Should have a separator character in the log file: "); 
                    _separator = char::from(value);
                }
            }

            if !proto_type_set
            {
                let proto_ref = line.as_ref();
                let result: Vec<&str> = proto_ref.expect("proto_ref")
                    .split(_separator).collect::<Vec<&str>>();
                if result[0] == "#path"
                {
                    proto_type_set = true;
                    proto_type.push(result[1].to_string());
                }
            }

            if !fields_set
            {
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

            if fields_set
            {
                let data = line.as_ref().expect("values should be refd")
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
            }
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
            if let Some(mapkey) = map.get_mut(field)
            {
                mapkey.push(item.to_string());
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
                        //dbg!(&mapkey,&item,&field, &item);
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
        for (outer_key, middle_map) in self.data.iter_mut() 
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
            self.data.remove(&key);
        }
    }

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

            if !self.data.contains_key(&proto) && !(proto == ZeekProtocol::NONE)
            {
                // To handle post processing easier, convert the inner
                // vector to a hashmap and return it. 
                let mut hp = HashMap::<String, HashMap<String, Vec<String>>>::new();
                hp.insert(p[1].to_string(), HashMap::<String, Vec::<String>>::new());
                self.data.insert(proto.clone(), hp);
            }

            // Create time range (e.g. 00-01) and use as keys to BTreeMap.
            if let Some(value) = self.data.get_mut(&proto) 
            {
                value.insert(p[1].to_string(), HashMap::<String, Vec::<String>>::new());
            }

            // Only pass the vector corresponding to the proto.
            if let Some(t) = self.data.get_mut(&proto) 
            {
                if let Some(g) = t.get_mut(&p[1].to_string())
                {
                    // thread here?
                    ////////////////////////////////////////
                    // spawn a thread for each param and arc 
                    //let mut bits = [0; 8];
                    //for i in 0..8 
                    //{
                    //    bits[7 - i] = (search >> i) & 1;
                    //    dbg!(bits[i]);
                    //}
                    ///////////////////////////////////
                    let _ = Self::read(log.path().as_path(), g, search, params);
                }
            }
        }
        //dbg!(&self);
        Self::_reduce(self);
        return Ok(())
    }
}

