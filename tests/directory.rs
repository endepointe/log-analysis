use log_analyzer::{LogType, LogHeader, LogDirectory, SearchParams};
use std::path::Path;

#[test]
fn test_create_heirarchy() -> Result<(), String>
{
    let s = LogDirectory::new(Path::new("zeek-test-logs/2024-07-02"));
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
