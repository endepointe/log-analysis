use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log_directory::ZeekLogDirectory,
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
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
    let s = ZeekLogDirectory::new(None);
    dbg!(&s);
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
}

#[test]
fn test_search_start_date_pass()
{
    let params = ZeekSearchParamsBuilder::default()
        .start_date("2024-07-02")
        .end_date(None)
        .log_type(None)
        .ip(None)
        .build()
        .unwrap();

    let mut loc = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));

    match &mut loc 
    {
        Ok(dir) => {
            let res = dir.search(&params);
            //dbg!(&res);
            assert!(res.is_ok());
            let res = res.unwrap();

            /*
            if let Some(s) = &res.get(&ZeekProtocol::CONN)
            {
                if let Some(d) = &s.get("00:00:00-01:00:00") 
                {
                    for key in d.keys()  
                    {
                        dbg!(&key);
                    }
                }
            }
            println!("");
            if let Some(s) = &res.get(&ZeekProtocol::SSH)
            {
                if let Some(d) = &s.get("00:00:00-01:00:00") 
                {
                    for key in d.keys()  
                    {
                        dbg!(&key);
                    }
                }
            }
            */
        }
        Err(_) => {
            dbg!("complete this error condition");
        }
    }
}

#[test]
fn test_search_start_date_fail()
{
    let params = ZeekSearchParamsBuilder::default()
        .start_date("2024-07")
        .end_date(None)
        .log_type(ZeekProtocol::CONN)
        .ip(None)
        .build()
        .unwrap();

    dbg!(&params);

    let mut loc = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));

    match &mut loc 
    {
        Ok(dir) => {
            let res = dir.search(&params);
            assert_eq!(res, Err(Error::SearchInvalidStartDate));
        }
        Err(_) => {
            dbg!("complete this error condition");
        }
    }
}

#[test]
fn test_check_date_format() 
{
    assert_eq!("2024-07-10", "2024-07-10");
}

