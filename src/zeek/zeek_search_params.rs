use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use std::str::FromStr;
use std::path::Path;
use derive_builder::Builder;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

//Reconsidering the necessity of start and end. Selecting one date
//and collecting on the userend is making more sense. 
#[derive(Debug, Default, Builder)]
#[builder(setter(into))]
#[builder(derive(PartialEq, Eq,))]
pub struct
ZeekSearchParams<'a>
{
    // default log path: /usr/local/zeek or /opt/zeek or custom/path/
    // https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough
    #[builder(default)]
    pub path_prefix: Option<&'a str>,
    #[builder(default)]
    pub selected_date: Option<&'a str>,
    #[builder(default)]
    pub start_date: Option<&'a str>,
    #[builder(default)]
    pub end_date: Option<&'a str>,
    #[builder(default)]
    pub proto_type: Option<&'a str>,//ZeekProtocol
    #[builder(default)]
    pub src_ip: Option<&'a str>,

}
impl<'a> ZeekSearchParams<'a>
{
    // learning the builder patter may solve issue of constructing 
    // params with required/wanted data.
    pub fn check(&self) -> u8 // 001, 101, etc.
    {
        // This current approach will result in pow(2,n) match arms, where n is the 
        // number of optionaln params in the struct.
        // At the least, there should be at least one param.
        // Returns specifies what searches to perform.
        match (&self.src_ip, &self.proto_type, &self.end_date)
        {
            (None, None, None) => return 0,
            (None, None, Some(_end)) => return 1, 
            (None, Some(_log), None) => return 2,
            (None, Some(_log), Some(_end)) => return 3,
            (Some(src_ip), None, None) => return 4,
            (Some(src_ip), None, Some(_end)) => return 5,
            (Some(src_ip), Some(_log), None) => return 6,
            (Some(src_ip), Some(_log), Some(_end)) => return 7,
            _ => return 8 // value should not be greater than 7.
                          // Starting day param is likely missing.
        }
    }

    pub fn get_selected_date_path(&self) -> String 
    {
        let mut search_path = String::new();

        if Self::path_prefix_exists(self) 
        {
            search_path.push_str(&self.path_prefix.unwrap());
            search_path.push_str("/");
            search_path.push_str(&self.selected_date.unwrap());
            search_path.push_str("/");
        } 
        else 
        {
            search_path.push_str(&self.selected_date.unwrap());
            search_path.push_str("/");
        }

        // check for ~ in path
        if search_path.as_bytes()[0] as u16 == 126 as u16
        {
            search_path.remove(0);
            search_path.insert_str(0, std::env::var("HOME")
                                   .expect("should exist on linux").as_str());
        }
        search_path
    }

    fn path_prefix_exists(&self) -> bool 
    {
        match &self.path_prefix 
        {
            Some(_) => { return true }
            None => { return false}
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
