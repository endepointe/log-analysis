use crate::zeek::zeek_log_header::ZeekLogHeader;
use std::collections::HashMap;

// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug, PartialEq, Eq)]
pub struct 
ZeekLogData<'a> 
{
    header: &'a ZeekLogHeader,
    data: HashMap<&'a str, Vec<&'a str>>,
}
impl<'a> ZeekLogData<'a>
{
    fn new(h: &'a ZeekLogHeader) -> Self
    {
        let fields = h.get_fields();
        let mut f = HashMap::<&'a str, Vec<&'a str>>::new();
        for field in fields
        {
            f.insert(&field, Vec::<&'a str>::new());
        }
        ZeekLogData {header: h, data: f}
    }
    fn add_field_entry(&mut self, key: &'a str, val: &'a str)
    {
        self.data.entry(key).or_insert(Vec::new()).push(val);
    }
}

