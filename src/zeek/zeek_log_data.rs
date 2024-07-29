use crate::zeek::zeek_log_header::ZeekLogHeader;
use std::collections::HashMap;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug, PartialEq, Eq)]
pub struct 
ZeekLogData<'a>
{
    //header: &'a ZeekLogHeader,
    //data: &'a mut HashMap<&'a str, Vec<&'a str>>,
    data: &'a HashMap<String, Vec<String>>
}
impl<'a> ZeekLogData<'a>
{

    pub fn read(p: &std::path::Path, data: &'a mut HashMap::<String, Vec<String>>) -> Self
    {
        let h : ZeekLogHeader = ZeekLogHeader::read(p);
        let h = h.clone();
        //let mut data = HashMap::new();
        //let mut f = HashMap::<&'a str, Vec<&'a str>>::new();
        for field in h.fields 
        {
            data.insert(field, Vec::<String>::new());
        }
        ZeekLogData { data }
    }

    //pub fn _read(h: &'a ZeekLogHeader) -> Self
    //{
    //    let fields = h.get_fields();
    //    let mut f = HashMap::<&'a str, Vec<&'a str>>::new();
    //    for field in fields
    //    {
    //        //std::thread::sleep(std::time::Duration::from_millis(500));
    //        //println!("Inserting field: {}", &field);
    //        f.insert(&field, Vec::<&'a str>::new());
    //    }
    //    ZeekLogData {header: h, data: f}
    //}
    //fn add_field_entry(&mut self, key: &'a str, val: &'a str)
    //{
    //    self.data.entry(key).or_insert(Vec::new()).push(val);
    //}
}

