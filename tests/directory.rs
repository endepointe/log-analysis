use log_analyzer::{LogType, LogHeader, LogDirectory, SearchParams};
use log_analyzer::PathError;
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
fn test_find_by_params()
{
    use std::io::Write;
    let mut input = String::new();
    print!("Enter the log path: ");
    std::io::stdout().flush().expect("stdout flush error");
    std::io::stdin().read_line(&mut input).expect("invalid input");

    println!("Checking log path: {}", input);
    let mut s = LogDirectory::new(Some(Path::new(input.trim())));
    let mut params = SearchParams::new();
    params.log_type = Some(LogType::CONN);
    params.ip = Some("81.81.2.2");
    println!("{:?}:{}", params, line!());
    //let result = s.find(params).unwrap();
    //println!("{:?} {}",result, line!());
    //let mut params = SearchParams::new();
    //params.log_type = Some(LogType::DNS);
    //println!("{:?}:{}", params, line!());
}

#[test]
fn test_check_date_format() 
{
    assert_eq!("2024-07-10", "2024-07-10");
}

