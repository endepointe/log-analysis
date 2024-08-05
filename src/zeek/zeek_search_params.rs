use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use std::str::FromStr;
use std::path::Path;
use derive_builder::Builder;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

// learn the builder pattern
#[derive(Debug, Default, Builder)]
#[builder(setter(into))]
#[builder(derive(PartialEq, Eq,))]
pub struct
ZeekSearchParams<'a>
{
    pub start_date: Option<&'a str>,
    pub end_date: Option<&'a str>,
    pub log_type: Option<ZeekProtocol>,
    pub ip: Option<&'a str>,
    #[builder(default = "4")]
    param_count: u8,
}
impl<'a> ZeekSearchParams<'a>
{
    pub fn get_param_count(&self) -> u8
    {
        self.param_count
    }

    // learning the builder patter may solve issue of constructing 
    // params with required/wanted data.
    pub fn check(&self) -> u8 // 0001, 0101, etc.
    {
        // This current approach will result in pow(n,2) match arms, where n is the 
        // number of params in the struct.
        // At the least, there should be at least one param.
        // Returns specifies what searches to perform.
        match (&self.ip, &self.log_type, &self.end_date, &self.start_date)
        {
            (None, None, None, None) => return 0,
            (None, None, None, Some(_start)) => return 1,
            (None, None, Some(_end), None) => return 2, // comb through all logs until end date
            (None, None, Some(_end), Some(_start)) => return 3,
            (None, Some(_log), None, None) => return 4,
            (None, Some(_log), None, Some(_start)) => return 5,
            (None, Some(_log), Some(_end), None) => return 6,
            (None, Some(_log), Some(_end), Some(_start)) => return 7,
            (Some(_ip), None, None, None) => return 8,
            (Some(_ip), None, None, Some(_start)) => return 9,
            (Some(_ip), None, Some(_end), None) => return 10,
            (Some(_ip), None, Some(_end), Some(_start)) => return 11,
            (Some(_ip), Some(_log), None, None) => return 12,
            (Some(_ip), Some(_log), None, Some(_start)) => return 13,
            (Some(_ip), Some(_log), Some(_end), None) => return 14,
            (Some(_ip), Some(_log), Some(_end), Some(_start)) => return 15,
            _ => return 0,
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

    pub fn set_end_date(&mut self, end: &'a Path) -> Result<(), Error>
    {
        match Self::check_date_format(end)
        {
            true => {
                self.end_date = Some(end.to_str().unwrap()); 
                Ok(())
            }
            false => {
                Err(Error::SearchInvalidEndDate)
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
                if let Err(_) = number 
                {
                    return false
                }
            }
            return true 
        } 
        false
    }
}
