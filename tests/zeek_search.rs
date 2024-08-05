use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::ZeekLog,
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
    types::helpers::print_type_of,
};
use std::path::Path;
use std::io::Write;

#[test]
fn test_env_vars()
{
    for (key, val) in std::env::vars() 
    {
        println!("{key} {val}");
    }
}

#[test]
fn test_create_log_directory()
{
    let dir = ZeekLog::new();
    dbg!(&dir);
    /*
    assert_eq!(s, Err(Error::PathPrefixUnspecified));

    let s = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));
    dbg!(&s);
    assert!(s.is_ok());

    // should look back to zeek-test-logs
    let s = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs/2024-07-03")));

    assert!(s.is_ok());

    let s = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs/2024-0a-02")));
    assert_eq!(s, Err(Error::PathNotFound));

    let s = ZeekLogDirectory::new(Some(Path::new("path/does/not/exist")));
    assert_eq!(s, Err(Error::PathNotFound));
    */
}

#[test]
fn test_search_0001_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .ip(None)
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
}

#[test]
fn test_search_0001_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07")
        .end_date(None)
        .log_type(None)
        .ip(None)
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert_eq!(res, Err(Error::SearchInvalidStartDate));

}

#[test]
fn test_print_time_ranges_proto_any()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .ip(None)
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    let mut res = res.unwrap();
    if let Some(proto) = res.get_mut(&ZeekProtocol::SSH) 
    {
        for key in proto.keys()
        {
            dbg!(&key);
        }
    }
}

#[test]
fn test_print_ip_proto_any()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .ip(None)
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    let res = res.unwrap();
    if let Some(proto) = res.get(&ZeekProtocol::CONN) 
    {
        // hashmap
        if let Some(entry) = proto.get("00:00:00-01:00:00") 
        {
            // hashmap
            print_type_of(&entry);
            dbg!(&entry.keys());
            if entry.contains_key("id.orig_h")
            {
                let ts = entry.get("ts").unwrap();
                let ip = entry.get("id.orig_h").unwrap();
                dbg!(&ts[0],&ip[0]);
            }
            
        }
    }
}
