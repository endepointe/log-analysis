use log_analyzer::{LogType, LogHeader, LogDirectory, SearchParams};
use std::path::Path;

#[test]
fn test_create_heirarchy() -> Result<(), String>
{
    // idea: trace through the filesystem when given a starting path. when 
    // the formatting is reached that matches yyyy-mm-dd, create the new log 
    // directory to be read.
    // Ideally, the user should supply the date to be read.
    let s = LogDirectory::new(Path::new("zeek-test-logs/2024-07-10"));
    assert!(s.is_ok());
    let mut params = SearchParams::new();
    let result = s?.find(params);
    println!("{result:?}");

    params.log_type = Some(LogType::CONN);

    let s = LogDirectory::new(Path::new("zeek-test-logs/2024-07-02"));
    let result = s?.find(params);
    println!("{}:{} -- {result:?}",file!(),line!());

    let s = LogDirectory::new(Path::new("path/does/not/exist"));
    assert!(s.is_err());
    Ok(())
}

#[test]
fn test_check_date_format() 
{
    assert_eq!("2024-07-10", "2024-07-10");
}
