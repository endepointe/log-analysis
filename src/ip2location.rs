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

    fn set_ip(&mut self, val: String) {self.ip = Some(val);}
    pub fn get_ip(&self) -> &Option<String> { &self.ip }
    fn set_country_code(&mut self, val: String) 
    {
        self.country_code= Some(val);
    }
    pub fn get_country_code(&self) -> &Option<String>
    {
        &self.country_code
    }
    fn set_country_name(&mut self, val: String) 
    {
        self.country_name = Some(val);
    }
    pub fn get_country_name(&self) -> &Option<String>
    {
        &self.country_name
    }
    fn set_region_name(&mut self, val: String) 
    {
        self.region_name = Some(val);
    }
    pub fn get_region_name(&self) -> &Option<String>
    {
        &self.region_name
    }
    fn set_city_name(&mut self, val: String) 
    {
        self.city_name = Some(val);
    }
    pub fn get_city_name(&self) -> &Option<String>
    {
        &self.city_name
    }
    fn set_latitude(&mut self, val: String) 
    {
        self.latitude = Some(val);
    }
    pub fn get_latitude(&self) -> &Option<String>
    {
        &self.latitude
    }
    fn set_longitude(&mut self, val: String) 
    {
        self.longitude = Some(val);
    }
    pub fn get_longitude(&self) -> &Option<String>
    {
        &self.longitude
    }
    fn set_zip_code(&mut self, val: String) 
    {
        self.zip_code = Some(val);
    }
    pub fn get_zip_code(&self) -> &Option<String>
    {
        &self.zip_code
    }
    fn set_time_zone(&mut self, val: String) 
    {
        self.time_zone = Some(val);
    }
    pub fn get_time_zone(&self) -> &Option<String>
    {
        &self.time_zone
    }
    fn set_auto_system_num(&mut self, val: String) 
    {
        self.auto_system_num = Some(val);
    }
    pub fn get_auto_system_num(&self) -> &Option<String>
    {
        &self.auto_system_num
    }
    fn set_auto_system_name(&mut self, val: String) 
    {
        self.auto_system_name = Some(val);
    }
    pub fn get_auto_system_name(&self) -> &Option<String>
    {
        &self.auto_system_name
    }
    fn set_is_proxy(&mut self, val: String) 
    {
        self.is_proxy = Some(val);
    }
    pub fn get_is_proxy(&self) -> &Option<String>
    {
        &self.is_proxy
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
                    dbg!(&item);
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

// For now, the local db will remain during development. Eventually, a database
// will exist to retrieve known IP addresses and store new log dates. This library 
// is will primarily function as a custom solution that takes care of retrieving logs,
// populating a database, returning relevant summaries for the client.
pub fn request(ip_addr: &String) -> Result<String, String>
{
    let local_json_db = std::env::var("LOCAL_JSON_DB").unwrap();
    let local_json_db = local_json_db.as_str();
    if local_json_db == "ip2loc.json"
    {
        use std::io::BufRead;
        let file = std::fs::File::open(local_json_db).expect("local json db should exist"); 
        let mut buffer = String::new();
        let mut reader = std::io::BufReader::new(&file);
        let mut res = String::new();
        let mut found: bool = false;
        let mut count = 0;
        let mut lines_iter = reader.lines().map(|line| line.unwrap());
        while let Some(line) = lines_iter.next()
        {
            if line.contains(ip_addr.as_str())
            {
                res.push_str("{");
                res.push_str(&line);
                while count < 11 // 12 items expected in the free tier ip2location response.
                {
                    let line = lines_iter.next().unwrap();
                    let line = line.replace('\t',"").replace('\r',"")
                        .replace('\n',"").replace(' ',"");
                    res.push_str(&line);
                    count = count + 1;
                }
                res.push_str("}");
                return Ok(res);
            }
        }
    } 
    else
    {
        let api_key = std::env::var("IP2LOCATION_API_KEY")
            .expect("add IP2LOCATION_API_KEY to $CARGO_HOME/config.toml");
        let url = format!("https://api.ip2location.io/?key={}&ip={}&format=json",api_key, ip_addr.as_str());
        let client = Client::new();
        let b = client.get(url).send();
        if let Ok(res) = b
        {
            let res = res.text().unwrap();
            return Ok(res);
        }
    }
    Err("create an error for this at some point".to_string())
}

