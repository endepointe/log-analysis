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
