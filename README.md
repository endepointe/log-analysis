# log-analysis 


# Overview 
Tools such as Kibana, Wazuh, Grafana, and SecurityOnion provide excellent solutions for ingesting and visualizing data. While the benefit of such tools cannot be understated, there are times when it is helpful to have an option to examine data where resources are limited. Using zeek logs, the following demonstration project aims to provide such a solution. 

![Demo](demo.gif)

## Get Ip2location API key

- Create an account on `https://www.ip2location.io/`.

- Add your ip2location api key and the LOCAL_JSON_DB env variables to `$CARGO_HOME/config.toml` 

Example config.toml: 

```bash
$ cat ~/.cargo/config.toml)
[env]
IP2LOCATION_API_KEY="yourip2locationapikey"
```

## Install and run 

```bash
### Install rust (if not already):
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

### Clone repo:
$ git clone https://github.com/endepointe/log-analysis.git
$ cd log-analysis
$ sh decrypt.sh 

### Enter the passphrase submitted along with the challenge.
### Otherwise, use your own zeek log data (in tsv format) to demo this tool.
$ sh run.sh

### May take a minute to query ip results. 
### Presents an opportunity to solve with threading.
```

## Usage (also See TEsTing)

- Scroll Up/Down: &#8593; / &#8595;
- Change tabs: &#8592; / &#8594;
- Toggle menu: Esc
    - Toggle additional info: i
- Toggle focus: Tab

## TEsTing

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
