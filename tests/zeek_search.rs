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
#[cfg(feature = "ip2location")]
fn test_env_vars()
{
    use std::env;
    match env::var("CARGO_HOME")
    {
        Ok(val) => println!("found: {val}"),
        Err(err) => println!("{err}")
    }
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
#[cfg(feature = "ip2location")]
#[cfg(feature = "noquery")]
fn test_cfg_ip2location_noquery()
{
    //let path = std::path::Path::new("ip.db");
    //let mut file = std::fs::File::create(&path).expect("should be able to create the file.");
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-02")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
}

#[test]
#[cfg(feature = "ip2location")]
fn test_cfg_ip2location()
{
    //let path = std::path::Path::new("ip.db");
    //let mut file = std::fs::File::create(&path).expect("should be able to create the file.");
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-02")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
}
 
#[test]
fn _write_to_file()
{
    let path = std::path::Path::new("ip.db");
    let mut file = std::fs::File::create(&path).expect("should be able to create the file.");

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-02")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.summary.len() == 0);
    for (ip, _) in &log.summary
    {
        writeln!(file, "{}", ip).expect("should have written ip address to file");
    }

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-03")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.summary.len() == 0);
    for (ip, _) in &log.summary
    {
        writeln!(file, "{}", ip).expect("should have written ip address to file");
    }

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-04")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.summary.len() == 0);
    for (ip, _) in &log.summary
    {
        writeln!(file, "{}", ip).expect("should have written ip address to file");
    }
    use std::os::unix::fs::PermissionsExt;
    use std::fs::Permissions;
    let permissions = Permissions::from_mode(0o444);
    file.set_permissions(permissions).expect("should have been able to set permissions on file");
}

#[test]
fn test_create_log()
{
    let dir = ZeekLog::new();
    assert_eq!(true, dir.summary.is_empty());
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-02")
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
fn test_search_date()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-03")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    //dbg!(&res);
    assert!(res.is_ok());
    //dbg!(&log.summary);
    //assert_eq!(false, log.summary.len() == 0);
    dbg!(&log.summary.keys());
    dbg!(&log.raw.keys());
}

#[test]
#[cfg(feature = "ip2location")]
fn test_search_date_ip2location()
{

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-03")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    //dbg!(&res);
    assert!(res.is_ok());
    //dbg!(&log.summary);
    //assert_eq!(false, log.summary.len() == 0);
    dbg!(&log.summary.keys());
    dbg!(&log.raw.keys());
}


#[test]
fn test_search_ip()
{
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-02")
        .src_ip("43.134.231.178")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.summary.len() == 0);
    dbg!(log.summary);

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("~/dev/log-analysis/zeek-test-logs")
        .selected_date("2024-07-03")
        .src_ip("43.134.231.178")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(true, log.summary.len() == 0);
    dbg!(log.summary.keys());
    dbg!(&log.raw.keys());
}

#[test]
#[cfg(feature = "ip2location")]
fn test_search_ip_location()
{
    // this test requires a date and can be used to gather all ip
    // addresses from start to end. see main.rs.
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .selected_date("2024-07-02")
        .src_ip("91.92.245.221")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.summary.len() == 0);
    dbg!(log.summary);

    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("~/dev/log-analysis/zeek-test-logs")
        .selected_date("2024-07-03")
        .src_ip("43.134.231.178")
        .build()
        .unwrap();
    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(true, log.summary.len() == 0);
    dbg!(log.summary.keys());
    dbg!(&log.raw.keys());
}
//#[test]
//fn test_search_ip_proto_pass()
//{
//    let params = ZeekSearchParamsBuilder::default()
//        .path_prefix("zeek-test-logs")
//        .start_date("2024-07-02")
//        .src_ip("43.134.231.178")
//        .proto_type("WEird")
//        .build()
//        .unwrap();
//    let mut log = ZeekLog::new();
//    let res = log.search(&params);
//    assert!(res.is_ok());
//    assert_eq!(false, log.summary.len() == 0);
//    //dbg!(log.summary);
//}
//
//#[test]
//fn test_search_ip_proto_fail()
//{
//    let params = ZeekSearchParamsBuilder::default()
//        .path_prefix("zeek-test-logs")
//        .start_date("2024-07-02")
//        .src_ip("43.134.231.178")
//        .proto_type("htTp")
//        .build()
//        .unwrap();
//    let mut log = ZeekLog::new();
//    let res = log.search(&params);
//    assert_eq!(true, log.summary.len() == 0);
//    //dbg!(log.summary);
//}
