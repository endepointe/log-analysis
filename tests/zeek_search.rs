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
fn test_search_000_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .src_ip(None)
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    //dbg!(res);
}

#[test]
fn test_search_000_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07")
        .end_date(None)
        .log_type(None)
        .src_ip(None)
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert_eq!(res, Err(Error::SearchInvalidStartDate));

}

#[test]
fn test_search_100_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .src_ip("43.134.231.178")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    let res = res.unwrap();
    dbg!(res);
}

#[test]
fn test_search_100_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .src_ip("3.14.23.8")// ip should not exist in the logs
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    let res = res.unwrap();
    dbg!(res);
}
