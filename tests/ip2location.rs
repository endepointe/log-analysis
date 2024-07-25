#[test]
#[cfg(feature = "ip2location")]
fn test_ip2location()
{
    use log_analysis::ip2location;
    ip2location();
}
