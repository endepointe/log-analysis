
# Log Analysis

This project provides a solution for analyzing Zeek logs stored on a remote server without copying the entire log files to a local machine. The system consists of a client application built with Tauri in Rust and a remote server service that handles log queries.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Remote Server Service](#remote-server-service)
  - [Client Application](#client-application)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Testing and Optimization](#testing-and-optimization)
- [Contributing](#contributing)
- [License](#license)

## Introduction

This project aims to provide an efficient way to analyze Zeek logs remotely. By using a client-server architecture, the solution ensures that large log files remain on the remote server, and only the queried results are transferred to the client application.

## Features

- Remote log querying without complete file transfer
- Secure communication between client and server
- Easy-to-use client application interface
- Flexible query handling on the server side

## Architecture

The system is divided into two main components:

1. **Remote Server Service**: A Rust-based service using Actix-web to handle incoming queries and process log data.
2. **Client Application**: A Tauri-based client application that sends queries to the remote server and displays the results.

## Prerequisites

- Rust (latest stable version)
- Node.js (for Tauri)
- Zeek installed on the remote server

## Setup

### Remote Server Service

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/zeek-log-analyzer.git
   cd zeek-log-analyzer/server
   ```

2. **Install dependencies**:
   ```bash
   cargo build
   ```

3. **Configure Zeek log paths**:
   Modify the paths in the server code to point to your Zeek log files.

4. **Run the server**:
   ```bash
   cargo run
   ```
   The server will start listening on `http://0.0.0.0:8080`.

### Client Application

1. **Navigate to the client directory**:
   ```bash
   cd ../client
   ```

2. **Install dependencies**:
   ```bash
   yarn tauri dev
   ```

3. **Build and run the client**:
   ```bash
   yarn tauri build
   ./target/release/bundle/your-app-name
   ```

## Usage

1. Start the remote server service.
2. Open the client application.
3. Enter your query filter in the input field and click "Query Logs".
4. The results will be displayed in the application interface.

## Security Considerations

- Use HTTPS for secure communication between the client and server.
- Implement authentication and authorization mechanisms to control access.
- Validate and sanitize inputs to prevent injection attacks.

## Testing and Optimization

- Test with various query filters to ensure robustness.
- curl -X POST http://localhost:8080/graphql -H "Content-Type: application/json" -d '{"query": "{ zeekLogs }"}'

- Optimize log querying for performance, potentially using advanced log processing tools or indexing strategies.

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any improvements or bug fixes.

## License

This project is licensed under the MIT License.

