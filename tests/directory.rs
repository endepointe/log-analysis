use log_analysis::{LogType, LogHeader, LogDirectory, SearchParams, SearchError};
use log_analysis::PathError;
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
    assert_eq!(s, Err(PathError::PrefixUnspecified));

    let s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    dbg!(&s);
    assert!(s.is_ok());

    // should look back to zeek-test-logs
    let s = LogDirectory::new(Some(Path::new("zeek-test-logs/2024-07-03")));
    assert!(s.is_ok());

    let s = LogDirectory::new(Some(Path::new("zeek-test-logs/2024-0a-02")));
    assert_eq!(s, Err(PathError::NotFound));

    let s = LogDirectory::new(Some(Path::new("path/does/not/exist")));
    assert_eq!(s, Err(PathError::NotFound));
}



#[test]
fn test_find()
{
    let mut params = SearchParams::new(Path::new("2024-07"));
    assert_eq!(params, Err(SearchError::InvalidDate));

    let mut params = SearchParams::new(Path::new("2024-07-02"));
    assert!(params.is_ok());

    let mut s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let _ = dir.find(&params.unwrap());
        }
        Err(_) => {
            todo!();
        }
    }

    let mut params = SearchParams::new(Path::new("2024-07-30"));
    assert!(params.is_ok());

    let mut s = LogDirectory::new(Some(Path::new("zeek-test-logs")));
    match &mut s 
    {
        Ok(dir) => {
            let invalid = dir.find(&params.unwrap());
            assert_eq!(invalid, Err(SearchError::InsufficientParams));
        }
        Err(_) => {
            todo!();
        }
    }
}

#[test]
fn test_check_date_format() 
{
    assert_eq!("2024-07-10", "2024-07-10");
}

