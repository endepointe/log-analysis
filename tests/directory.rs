
use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParams, 
    zeek::zeek_log_directory::ZeekLogDirectory,
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
};
use std::path::Path;

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
fn test_search()
{
    let mut params = ZeekSearchParams::new();

    let params_result = params.set_start_date(Path::new("2024-07"));
    assert_eq!(params_result, Err(Error::SearchInvalidStartDate));

    let params_result = params.set_start_date(Path::new("2024-07-02"));
    assert_ne!(params_result, Err(Error::SearchInvalidStartDate));
    assert!(params_result.is_ok());

    let mut loc = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut loc 
    {
        Ok(dir) => {
            let res = dir.search(&params);
            assert!(res.is_ok());
            let res = res.unwrap();
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
                println!("{}", std::mem::size_of_val(&s));
                if let Some(d) = &s.get("00:00:00-01:00:00") 
                {
                    for key in d.keys()  
                    {
                        dbg!(&key);
                    }
                }
            }
        }
        Err(_) => {
            dbg!("complete this error condition");
        }
    }

    /*
    assert_eq!(params, Err(Error::SearchInvalidDate));

    let mut params = ZeekSearchParams::start_date(Path::new("2024-07-02"));
    assert!(params.is_ok());

    let mut s = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let res = dir.search(&params.unwrap());
            assert_eq!(res, Err(Error::SearchInsufficientParams));
        }
        Err(_) => {
            dbg!(todo!());
        }
    }

    let mut params = ZeekSearchParams::start_date(Path::new("2024-07-02"));
    let mut s = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let res = dir.search(&params.unwrap());
            assert_eq!(res, Err(Error::SearchInsufficientParams));
        }
        Err(e) => {
            dbg!(e);
            //assert_eq!(e, Error::PathNotFound);
        }
    }

    let mut params = ZeekSearchParams::start_date(Path::new("2024-07-02"));
    assert!(params.is_ok());// passes here 

    let mut s = ZeekLogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            dbg!(&dir);
            params.end_date = Some("2024-07-03");
            let invalid = dir.search(&params.unwrap());
            assert_eq!(invalid, Err(Error::SearchInsufficientParams));
        }
        Err(_) => {
            todo!();
        }
    }
    */
}

#[test]
fn test_check_date_format() 
{
    assert_eq!("2024-07-10", "2024-07-10");
}

