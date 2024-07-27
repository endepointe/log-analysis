use log_analysis::{LogType, LogHeader, LogDirectory, SearchParams, Error};
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
    let s = LogDirectory::new(None);
    dbg!(&s);
    assert_eq!(s, Err(Error::PathPrefixUnspecified));

    let s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    dbg!(&s);
    assert!(s.is_ok());

    // should look back to zeek-test-logs
    let s = LogDirectory::new(Some(Path::new("zeek-test-logs/2024-07-03")));
    assert!(s.is_ok());

    let s = LogDirectory::new(Some(Path::new("zeek-test-logs/2024-0a-02")));
    assert_eq!(s, Err(Error::PathNotFound));

    let s = LogDirectory::new(Some(Path::new("path/does/not/exist")));
    assert_eq!(s, Err(Error::PathNotFound));
}



#[test]
fn test_find()
{
    let mut search = SearchParams::new();

    let search_result = search.set_start_date(Path::new("2024-07"));
    assert_eq!(search_result, Err(Error::SearchInvalidStartDate));

    let search_result = search.set_start_date(Path::new("2024-07-02"));
    assert_ne!(search_result, Err(Error::SearchInvalidStartDate));
    assert!(search_result.is_ok());

    let mut s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let res = dir.find(&search);
            assert!(res.is_ok());
        }
        Err(_) => {
            dbg!(todo!());
        }
    }

    /*
    assert_eq!(params, Err(Error::SearchInvalidDate));

    let mut params = SearchParams::start_date(Path::new("2024-07-02"));
    assert!(params.is_ok());

    let mut s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let res = dir.find(&params.unwrap());
            assert_eq!(res, Err(Error::SearchInsufficientParams));
        }
        Err(_) => {
            dbg!(todo!());
        }
    }

    let mut params = SearchParams::start_date(Path::new("2024-07-02"));
    let mut s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let res = dir.find(&params.unwrap());
            assert_eq!(res, Err(Error::SearchInsufficientParams));
        }
        Err(e) => {
            dbg!(e);
            //assert_eq!(e, Error::PathNotFound);
        }
    }

    let mut params = SearchParams::start_date(Path::new("2024-07-02"));
    assert!(params.is_ok());// passes here 

    let mut s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            dbg!(&dir);
            params.end_date = Some("2024-07-03");
            let invalid = dir.find(&params.unwrap());
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

