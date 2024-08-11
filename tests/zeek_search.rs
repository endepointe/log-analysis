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
    //for (key, val) in std::env::vars() 
    //{
    //    println!("{key} {val}");
    //}
}

#[test]
fn test_create_log()
{
    let dir = ZeekLog::new();
    assert_eq!(true, dir.data.is_empty());
}
// 0    0           0
// ip   log_type    end_date
#[test]
fn test_search_params()
{
    let params = ZeekSearchParamsBuilder::default().build();
    assert!(params.is_ok());
    dbg!(&params);
}

#[test]
fn test_search_000_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    dbg!(std::mem::size_of_val(&res));
    //dbg!(res);
}

#[test]
fn test_search_000_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert_eq!(res, Err(Error::SearchInvalidStartDate));
    dbg!(std::mem::size_of_val(&res));
}

#[test]
fn test_search_100_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("43.134.231.178")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
}

#[test]
fn test_search_100_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("3.14.23.8")// ip should not exist in the logs
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_empty());
}

#[test]
fn test_search_110_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("43.134.231.178")
        .log_type("weird")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();

    let res = log.search(&params);
    assert!(res.is_ok());
}

#[test]
fn test_search_110_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("43.134.231.178")
        .log_type("http")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    dbg!(&res);
    assert_eq!(true, res.expect("should be Ok(BTreeMap)").is_empty());
}
