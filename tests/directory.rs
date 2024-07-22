use log_analyzer::{LogType, LogHeader, LogDirectory, SearchParams};
use std::path::Path;

#[test]
fn test_create_log_directory() -> Result<(), String>
{
    // idea: trace through the filesystem when given a starting path. when 
    // the formatting is reached that matches yyyy-mm-dd, create the new log 
    // directory to be read.
    // Ideally, the user should supply the date to be read.
    let s = LogDirectory::new(Path::new("zeek-test-logs/2024-07-03"));
    assert!(s.is_ok());

    let s = LogDirectory::new(Path::new("zeek-test-logs/2024-0a-02"));
    assert!(s.is_err());

    let s = LogDirectory::new(Path::new("path/does/not/exist"));
    assert!(s.is_err());
    Ok(())
}

#[test]
fn test_find_by_params()
{
    let mut s = LogDirectory::new(Path::new("zeek-test-logs/2024-07-03")).unwrap();
    let mut params = SearchParams::new();
    params.log_type = Some(LogType::CONN);
    params.ip = Some("81.81.2.2");
    println!("{:?}:{}", params, line!());
    let result = s.find(params).unwrap();
    println!("{:?} {}",result, line!());
    //let mut params = SearchParams::new();
    //params.log_type = Some(LogType::DNS);
    //println!("{:?}:{}", params, line!());
}

#[test]
fn test_check_date_format() 
{
    assert_eq!("2024-07-10", "2024-07-10");
}
