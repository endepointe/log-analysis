use log_analyzer::{Search, LogHeader, LogData};
#[test]
fn test_search_ip_addr()
{
    let s = Search::new();
    let ip = s.ip_addr("127.0.0.1").unwrap();
    assert_eq!(ip, "127.0.0.1");
    println!("{ip:?}");
    s.test(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127,0,0,1)));
}
