# log-analysis (not complete)

Rust library designed for extracting relevant information from zeek logs.


![Demo](demo.gif)


## Installation

`cargo add log-analysis`

## Usage (also See TEsTing)

```bash
cargo run --features ip2location
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
