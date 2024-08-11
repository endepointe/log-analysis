# log-analysis (not complete)

Rust library designed for extracting relevant information from zeek logs.

Results returned in a BTreeMap for furth processing.

## Installation

cargo add log_analysis

## Usage
```rust
let search_params = ZeekSearchParamsBuilder::default()
    .path_prefix("zeek-test-logs")
    .start_date("2024-07-02")
    .src_ip("43.134.231.178")
    .build()
    .unwrap();
let mut log = ZeekLog::new();
let res = log.search(&params); // Ok(LogTree)
// use res as needed in your application
```

## Testing

Testing is straightforward. Tests located in tests/. Test-case addtions welcomed in PRs.

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
