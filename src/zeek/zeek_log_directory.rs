use crate::types::error::Error;
use crate::types::types::LogTree;
use crate::zeek::zeek_log_proto::ZeekProtocol;

use crate::zeek::zeek_log_data::ZeekLogData;
use crate::zeek::zeek_search_params::ZeekSearchParams;

use std::path::Path;
use std::collections::HashMap;
use std::collections::btree_map::BTreeMap;


#[derive(Debug, PartialEq, Eq)]
pub struct
ZeekLogDirectory<'a>
{
    // default log path: /usr/local/zeek or /opt/zeek or custom/path/
    // https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough
    path_prefix: Option<&'a str>,
    pub data: LogTree,
}
impl<'a> ZeekLogDirectory<'a>
{
    // Initializes structure to search through logs using the path_prefix/ as the
    // parent log directory.
    pub fn new(p: Option<&'a Path>) -> Result<Self, Error>
    {
        match p 
        {
            None => {
                // check whether the default paths exist
                let opt_zeek = std::path::Path::new("/opt/zeek/");
                let usr_local_zeek = std::path::Path::new("/usr/local/zeek/");
                if opt_zeek.is_dir() 
                {
                    return Ok(ZeekLogDirectory {
                        path_prefix: opt_zeek.to_str(),
                        data: BTreeMap::new(),
                    })
                } 
                if usr_local_zeek.is_dir() 
                {
                    return Ok(ZeekLogDirectory {
                        path_prefix: usr_local_zeek.to_str(),
                        data: BTreeMap::new(),
                    })
                } 
                return Err(Error::PathPrefixUnspecified)
            }
            Some(path) => {
                let parent_log_dir = std::path::Path::new(path);
                if parent_log_dir.is_dir() 
                {
                    return Ok(ZeekLogDirectory {
                        path_prefix: path.to_str(),
                        data: BTreeMap::new(),
                    })
                }
                return Err(Error::PathNotFound)
            }
        }
    }

    fn path_prefix_exists(&self) -> bool 
    {
        match &self.path_prefix 
        {
            Some(_) => { return true }
            None => { return false}
        }
    }

    pub fn search(&mut self, params: &ZeekSearchParams) -> Result<LogTree, Error> 
    {
        let search : u8 = params.check();

        // Somehow, this needs to be available at compile time.
        // For now, just set it to 8 for the bits and accept that the
        // msb will be zero.
        //let param_count = params.get_param_count(); 

        let mut bits = [0; 8];
        for i in 0..8 
        {
            bits[7 - i] = (search >> i) & 1;
            dbg!(bits[i]);
        }

        if search == 0 
        {
            return Err(Error::SearchInsufficientParams)
        } 
        let mut search_path = String::new();

        if Self::path_prefix_exists(self) 
        {
            search_path.push_str(&self.path_prefix.unwrap());
            search_path.push_str("/");
            search_path.push_str(params.start_date.unwrap());
            search_path.push_str("/");
        } 
        else 
        {
            search_path.push_str(params.start_date.unwrap());
            search_path.push_str("/");
        }

        let path = Path::new(search_path.as_str());

        match path.is_dir()
        {
            true => {
                match search
                {
                    // search start date for all
                    1 => { 
                        // This condition handles when only start date is provided. 
                        // Return all information about the logs.
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

                            // Only pass the vector corresponding to the time.
                            if let Some(t) = self.data.get_mut(&proto) 
                            {
                                if let Some(g) = t.get_mut(&p[1].to_string())
                                {
                                    // thread here?
                                    let _ = ZeekLogData::read(log.path().as_path(), g);
                                }
                            }
                        }
                    }
                    // search start date and ip
                    //5 => {
                    //    for entry in std::fs::read_dir(&path).expect("path to log dir should exist.")
                    //    {
                    //        
                    //    }
                    //}
                    _ => {
                        //dbg!(search);
                        return Ok(self.data.clone())
                    }
                }
                return Ok(self.data.clone())
            }
            false => {
                return Err(Error::SearchInvalidStartDate)
            }
        }
    }
}

