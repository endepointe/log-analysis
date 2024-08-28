pub mod ip2location;
use reqwest::blocking::Client;
use std::error::Error;
use std::sync::{Arc,Mutex};

use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_log::Data;
use crate::types::helpers::print_type_of;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IP2LocationResponse 
{
    ip: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    latitude: Option<String>, 
    longitude: Option<String>, 
    zip_code: Option<String>, 
    time_zone: Option<String>,
    auto_system_num: Option<String>,
    auto_system_name: Option<String>,
    is_proxy: Option<String>,
}

impl IP2LocationResponse
{
    pub fn new() -> Self//IP2LocationResponse 
    {
        IP2LocationResponse {
            ip: None,
            country_code: None,
            country_name: None,
            region_name: None,
            city_name: None,
            latitude: None, 
            longitude: None, 
            zip_code: None,
            time_zone: None,
            auto_system_num: None,
            auto_system_name: None,
            is_proxy: None,
        }
    }

    fn set_ip(&mut self, val: String) 
    {
        self.ip = Some(val);
    }
    fn set_country_code(&mut self, val: String) 
    {
        self.country_code= Some(val);
    }
    fn set_country_name(&mut self, val: String) 
    {
        self.country_name = Some(val);
    }
    fn set_region_name(&mut self, val: String) 
    {
        self.region_name = Some(val);
    }
    fn set_city_name(&mut self, val: String) 
    {
        self.city_name = Some(val);
    }
    fn set_latitude(&mut self, val: String) 
    {
        self.latitude = Some(val);
    }
    fn set_longitude(&mut self, val: String) 
    {
        self.longitude = Some(val);
    }
    fn set_zip_code(&mut self, val: String) 
    {
        self.zip_code = Some(val);
    }
    fn set_time_zone(&mut self, val: String) 
    {
        self.time_zone = Some(val);
    }
    fn set_auto_system_num(&mut self, val: String) 
    {
        self.auto_system_num = Some(val);
    }
    fn set_auto_system_name(&mut self, val: String) 
    {
        self.auto_system_name = Some(val);
    }
    fn set_is_proxy(&mut self, val: String) 
    {
        self.is_proxy = Some(val);
    }
    pub fn create(&mut self, data: &str)
    {
        if let Some(data) = data.strip_prefix("{") 
        {
            if let Some(data) = data.strip_suffix("}")
            {
                let data: Vec<&str> = data.split(',').collect();
                for prop in data.iter()
                {
                    let item = &prop.split(':').collect::<Vec<&str>>();
                    match item[0].trim_matches('"')
                    {
                        "ip" => {self.set_ip(String::from(item[1].trim_matches('"')));},
                        "country_code" => {self.set_country_code(String::from(item[1].trim_matches('"')));},
                        "country_name" => {self.set_country_name(String::from(item[1].trim_matches('"')));},
                        "region_name" => {self.set_region_name(String::from(item[1].trim_matches('"')));},
                        "city_name" => {self.set_city_name(String::from(item[1].trim_matches('"')));},
                        "latitude" => {self.set_latitude(String::from(item[1].trim_matches('"')));},
                        "longitude" => {self.set_longitude(String::from(item[1].trim_matches('"')));},
                        "zip_code" => {self.set_zip_code(String::from(item[1].trim_matches('"')));},
                        "time_zone" => {self.set_time_zone(String::from(item[1].trim_matches('"')));},
                        "asn" => {self.set_auto_system_num(String::from(item[1].trim_matches('"')));},
                        "as" => {self.set_auto_system_name(String::from(item[1].trim_matches('"')));},
                        "is_proxy" => {self.set_is_proxy(String::from(item[1].trim_matches('"')));},
                        _ => println!("implement {:?}", &item[0]),
                    }
                }
            }
        };
    }
}

pub fn request(ip_addr: &String) -> Result<String, String>
{
    let api_key = std::env::var("IP2LOCATION_API_KEY")
        .expect("add IP2LOCATION_API_KEY to $CARGO_HOME/config.toml");
    let url = format!("https://api.ip2location.io/?key={}&ip={}&format=json",api_key, ip_addr.as_str());
    let client = Client::new();
    let b = client.get(url).send();
    dbg!(&b);
    if let Ok(res) = b
    {
        let res = res.text().unwrap();
        return Ok(res);
    }
    Err("create an error for this at some point".to_string())
}

