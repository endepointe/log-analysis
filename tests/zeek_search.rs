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
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .build().unwrap();
    dbg!(params);
    let dir = ZeekLog::new();
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
    dbg!(std::mem::size_of_val(&res));
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
    dbg!(std::mem::size_of_val(&res));
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
    let mut res = res.unwrap();
    println!("Before key removal: ");
    dbg!(&res.keys());
    if let Some(day) = res.get(&ZeekProtocol::HTTP) 
    {
        dbg!(&day);
    }
    // removes all the empty BTreeMap keys that have empty children.
    // throw this in a reducer function tomorrow morning for better 
    // results.
    let mut keys_to_remove = Vec::new();
    for (outer_key, middle_map) in res.iter_mut() 
    {
        let mut middle_keys_to_remove = Vec::new();
        for (middle_key, inner_map) in middle_map.iter_mut() 
        {
            let mut inner_keys_to_remove = Vec::new();
            for (inner_key, vec) in inner_map.iter_mut() 
            {
                if vec.is_empty() 
                {
                    inner_keys_to_remove.push(inner_key.clone());
                }
            }
            for key in inner_keys_to_remove 
            {
                inner_map.remove(&key);
            }
            if inner_map.is_empty() 
            {
                middle_keys_to_remove.push(middle_key.clone());
            }
        }
        for key in middle_keys_to_remove 
        {
            middle_map.remove(&key);
        }
        if middle_map.is_empty() 
        {
            keys_to_remove.push(outer_key.clone());
        }
    }
    for key in keys_to_remove 
    {
        res.remove(&key);
    }
    println!("After key removal:");
    dbg!(res.keys());

    //dbg!(std::mem::size_of_val(&res));
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
