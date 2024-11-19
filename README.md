
# Transparent Proxy for Logging and Injection

## Overview
This tool acts as a transparent proxy that can operate in either active or passive mode. It listens for HTTP requests, logs sensitive information, and in active mode, injects JavaScript for client-side data collection.

**Disclaimer**: This code is for educational and security research purposes only. Unauthorized use is illegal and unethical.

## Prerequisites
- Python 3.5
- Required libraries: `argparse`, `re`, `socket`, `zlib`, `gzip`, `io`, `urllib.parse`
- Ensure proper permissions to bind to the desired IP and port (root/admin)

## Usage
### Command-line Arguments
- `-m, --mode`: Specifies the mode of operation (`active` or `passive`). 
- `ip`: The IP address to listen on.
- `port`: The port to listen on.

### Running the Proxy
```bash
python proxy_logger.py -m <mode> <ip> <port>
```

### Example
To run the proxy in passive mode on IP `127.0.0.1` and port `8080`:
```bash
python proxy_logger.py -m passive 127.0.0.1 8080
```

To run in active mode:
```bash
python proxy_logger.py -m active 127.0.0.1 8080
```

## How It Works
### Passive Mode
- Logs sensitive information such as emails, passwords, and other personal data from requests and responses.
- Logs are stored in `info1.txt`.

### Active Mode
- Injects JavaScript into HTML responses to collect client-side data such as:
  - User-Agent
  - Screen resolution
  - Language preference
- Logs client information in `info2.txt`.
- Only HTML content is modified for JavaScript injection; other content types are forwarded unaltered.

### JavaScript Injection
- Injected script sends client data to the proxy server using an image request.

### Request and Response Handling
- **GET and POST Requests**: Requests are forwarded to the target server.
- **Phishing Page Serving**: If a `GET` request is detected for `example.com`, a sample login page is served.
- **Phishing Data Handling**: A `POST` to `/login` logs client information and responds with a `GET` to `https://example.com`.

### Decompression
- Supports decompression of `gzip` and `deflate` encoded responses for inspection and modification.

## Log Files
- **info1.txt**: Stores sensitive information extracted from requests and responses in passive mode.
- **info2.txt**: Stores client information logged in active mode.

## Important Notes
- This tool must be run responsibly and in compliance with legal and ethical standards.
- Ensure no unauthorized data collection occurs.

## License
This tool is provided as-is with no warranty. It is intended for educational and research purposes only.
