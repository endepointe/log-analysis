use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::ZeekLog,
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
    types::helpers::print_type_of,
};
use std::path::Path;
use std::io::{Read, Write};
use flate2::read::GzDecoder;

#[test]
fn test_env_vars()
{
    //for (key, val) in std::env::vars() 
    //{
    //    println!("{key} {val}");
    //}
}

#[test]
fn test_flate2()
{
    let file = std::fs::File::open("zeek-test-logs/2024-07-02/conn.00:00:00-01:00:00.log.gz")
                        .expect("conn file should exist");
    let mut s = String::new();
    let mut d = GzDecoder::new(file);
    d.read_to_string(&mut s).unwrap();

}

#[test]
fn test_create_log()
{
    let dir = ZeekLog::new();
    assert_eq!(true, dir.data.is_empty());
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
}

// 0    0           0
// ip   proto_type    end_date
#[test]
fn test_search_params()
{
    let params = ZeekSearchParamsBuilder::default().build();
    assert!(params.is_ok());
}

#[test]
fn test_search_000_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-03")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    //dbg!(&res);
    assert!(res.is_ok());
    //dbg!(&log.data);
    assert_eq!(false, log.data.len() == 0);
    //dbg!(log.data);
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
    assert_eq!(false, log.data.len() == 0);
    dbg!(log.data);

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("~/dev/log-analysis/zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("43.134.231.178")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.data.len() == 0);
    //dbg!(log.data);
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
}

#[test]
fn test_search_110_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("43.134.231.178")
        .proto_type("WEird")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.data.len() == 0);
    //dbg!(log.data);
}

#[test]
fn test_search_110_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .src_ip("43.134.231.178")
        .proto_type("htTp")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert_eq!(true, log.data.len() == 0);
    //dbg!(log.data);
}
