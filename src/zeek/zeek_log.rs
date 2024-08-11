use crate::types::error::Error;
use crate::types::types::LogTree;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_search_params::ZeekSearchParams;
use crate::types::helpers::print_type_of;
use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct
ZeekLog
{
    // default log path: /usr/local/zeek or /opt/zeek or custom/path/
    // https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough
    //path_prefix: Option<&'a str>,
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
        let output = std::process::Command::new("zcat")
            .arg(&p)
            .output()
            .expect("failed to zcat the log file");
        let log_header = output.stdout;

        let mut _separator : char = ' ';
        let mut fields = Vec::<String>::new(); 

        match std::str::from_utf8(&log_header) 
        {
            Ok(v) => {
                // Read the header.
                let line: Vec<&str> = v.split('\n').collect();
                let result = line[0].split(' ')
                                .collect::<Vec<&str>>()[1]
                                .strip_prefix("\\x");

                // Case when file does not have header info.
                // This should not return an error due to the calling function's 
                // check. Leaving here until something useful is needed from the 
                // logs without a header.
                if result == None { 
                    return Err(Error::NoLogHeader) 
                } 

                let result = u8::from_str_radix(result.unwrap().trim(), 16)
                    .expect("Should have a separator character in the log file: "); 

                _separator = char::from(result);

                let s = line[6].split(_separator).collect::<Vec<_>>();

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

                // Load the data based on search_bits
                match search_bits
                {
                    0 => {Self::_000(_separator, &line, map, &data);}
                    4 => {Self::_100(_separator, &line, map, &data, params);}
                    6 => {
                        let log_type : &Vec<&str> = &line[4].split(_separator).collect();
                        Self::_110(_separator, &line, map, &data, params, 
                                   ZeekProtocol::read(log_type[1]));
                    }
                    _ => {}
                }
            }
            Err(_) => {
                return  Err(Error::Unspecified) 
            }
        }
        Ok(())
    }
    // date (all)
    fn _000(c: char, line: &Vec<&str>, map: &mut HashMap<String, Vec<String>>, data: &Vec<String>) 
    {
        for n in 8..line.len() // line.len() - 2 == #close\tdate which is not used.
        {
            let items = line[n].split(c).collect::<Vec<_>>();
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
    // ip
    fn _100(c: char, 
            line: &Vec<&str>, 
            map: &mut HashMap<String, Vec<String>>, 
            data: &Vec<String>,
            params: &ZeekSearchParams) 
    {
        //dbg!(&params.src_ip);
        let src_ip = params.src_ip.unwrap();
        for n in 8..line.len() // line.len() - 2 == #close\tdate which is not used.
        {
            let items = line[n].split(c).collect::<Vec<_>>();
            if items[0] == "#close" {break;}
            for item in 0..items.len() - 1
            {
                if let Some(m) = map.get_mut(&data[item])
                {
                    if &items[2] == &src_ip 
                    {
                        m.push(items[item].to_string());
                    }
                }
            }
        }
    }

    // ip + log_type
    fn _110(c: char, 
            line: &Vec<&str>, 
            map: &mut HashMap<String, Vec<String>>, 
            data: &Vec<String>,
            params: &ZeekSearchParams,
            proto: ZeekProtocol) 
    {        
        if let Some(t) = &params.log_type
        {
            if ZeekProtocol::read(&t) == proto 
            {
                let src_ip = params.src_ip.unwrap();
                for n in 8..line.len() // line.len() - 2 == #close\tdate which is not used.
                {
                    let items = line[n].split(c).collect::<Vec<_>>();
                    if items[0] == "#close" {break;}
                    for item in 0..items.len() - 1
                    {
                        if let Some(m) = map.get_mut(&data[item])
                        {
                            if &items[2] == &src_ip 
                            {
                                m.push(items[item].to_string());
                            }
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

    pub fn search(&mut self, params: &ZeekSearchParams) -> Result<LogTree, Error> 
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
        Self::_reduce(self);
        return Ok(self.data.clone())
    }
}

