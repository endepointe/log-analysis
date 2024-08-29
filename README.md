# log-analysis (not complete)

Rust library designed for extracting relevant information from zeek logs.

## Installation

`cargo add log-analysis`

## Usage (See TEsTing)

Return an overview of that day:
```rust
// Data format returned: 
//struct Data
//{
//    ip_address: String,
//    frequency: usize,
//    connection_uids: Vec<UID>,
//    protocols: Vec<String>,
//    time_ranges: HashMap<String, u32>,
//    file_info: Vec<HashMap<String,String>>,
//    conn_state: Vec::<String>,
//    history: Vec::<String>,
//    dports: Vec<u16>,
//    country: Option<String>, //ip2loc
//    city: Option<String>, // ip2loc
//    isp: Option<String>, // ip2loc
//    malicious: bool, // virustotal?
//    bytes_transferred: u64,
//    related_ips: Vec<String>,
//}

let params = ZeekSearchParamsBuilder::default()
    .path_prefix("zeek-test-logs")
    .start_date("2024-07-02")
    .build()
    .unwrap();
let mut log = ZeekLog::new();
let res = log.search(&params); // Ok(())
assert_eq!(true, res.is_ok));
assert_eq!(false, log.data.is_empty())
let serialized = serde_json::to_string(&log.data);
assert!(serialized.is_ok());
```

Return specific data(fails tests, issue exists):
```rust
let params = ZeekSearchParamsBuilder::default()
    .path_prefix("zeek-test-logs")
    .start_date("2024-07-02")
    .src_ip("43.134.231.178")
    .proto_type("coNn")
    .build()
    .unwrap();
let mut log = ZeekLog::new();
let res = log.search(&params); // Ok(())
assert_eq!(true, res.is_ok));
assert_eq!(false, log.data.is_empty())
let serialized = serde_json::to_string(&log.data);
assert!(serialized.is_ok());
```
## TEsTing

While testing is straightforward, there are a few conditions that need to be met during development to save ip2location queries. 

You will want to create two files: `ip2loc.json` and a directory that is the parent directory to the days of existing zeek logs which are in YYYY-MM-DD format.

Create an account on `https://www.ip2location.io/` and use the `_write_to_file` test to create the `ip.db` file. Once created, create the `ip2loc.json` file using: `jq . ip.db > ip2loc.json`.

Add your ip2location api key and the LOCAL_JSON_DB env variables to `$CARGO_HOME/config.toml`.

At this point, you should be able to run the following test: 

`cargo test test_search_000_pass_ip2location --features ip2location -- --nocapture`

The setup and testing will improve, bear with me. If you run into any issues, please submit an issue. I am here to help.

Tests located in tests/. Test-case addtions welcomed in PRs.


### Performance
```bash
# Requires flamegraph and perf
# Repo: https://github.com/flamegraph-rs/flamegraph
cargo flamegraph --test <location>
```

## Contributing

Contributions are welcome! Please submit pull requests or open issues to improve the library.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
