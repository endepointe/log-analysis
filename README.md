# log-analysis (not complete)


Rust library designed to read and parse Zeek logs. It includes an optional `ip2location` feature for IP geolocation.

## Features

- Search through various logs, such as zeek, and return meaningful results for other applications.
- Optional IP geolocation using `ip2location`

## Installation

todo

## Usage
```rust
let log = "todo"
```

### Basic Usage

todo

### Using `ip2location` Feature

todo

## Features

- `ip2location`: Enables IP geolocation using the IP2Location database.

## Testing

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
