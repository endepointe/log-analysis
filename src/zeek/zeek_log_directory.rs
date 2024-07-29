use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_log::ZeekLog;
use crate::zeek::zeek_search_params::ZeekSearchParams;

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
ZeekLogDirectory<'a>
{
    path_prefix: Option<&'a str>,
    pub dates: BTreeMap<String, ZeekLog>,
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
                        dates: BTreeMap::new(),
                    })
                } 
                if usr_local_zeek.is_dir() 
                {
                    return Ok(ZeekLogDirectory {
                        path_prefix: usr_local_zeek.to_str(),
                        dates: BTreeMap::new(),
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
                        dates: BTreeMap::new(),
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
            Some(path) => { return true }
            None => { return false}
        }
    }

    fn check_params(&self, params: &ZeekSearchParams) -> u8 // 0001, 0101, etc.
    {
        // There must be a better way to check what params have been provided...
        // This current approach will result in pow(n,2) match arms, where n is the 
        // number of params in the struct.
        //
        // At the least, there should be at least one param.
        //
        // Returns a tuple that specifies what searches to perform.
        //
        match (&params.start_date, &params.end_date, &params.log_type, &params.ip) 
        {
            (None, None, None, None) => return 0,
            (Some(start), None, None, None) => return 1,
            (Some(start), Some(end), _log_type, _ip) => return 2,
            (Some(start), _end , Some(log_type), _ip) => return 3,
            (Some(start), _end , _log_type, Some(ip)) => return 4,
            _ => return 0,
        }
    }

    // requires a start date and one additional parameter.
    pub fn search(&self, params: &ZeekSearchParams) -> Result<(), Error> 
    {
        let search : u8 = Self::check_params(self, params);

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
                dbg!(&path);
                match search
                {
                    1 => { // only start date provided. return general information about the logs.
                        for entry in std::fs::read_dir(&path).expect("error reading path") 
                        {
                            let log = entry.unwrap();
                            let data = ZeekLog::read(log.path().as_path());
                            //dbg!(&data);
                            break;
                        }
                    }
                    _ => {
                        dbg!(search);
                        return Ok(())
                    }
                }
                return Ok(())
            }
            false => {
                return Err(Error::SearchInvalidStartDate)
            }
        }
        Ok(())
    }
}

