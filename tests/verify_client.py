import socket
import ssl
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 verify_client.py <port> <sni_hostname>")
        sys.exit(1)

    port = int(sys.argv[1])
    hostname = sys.argv[2]

    # Create a simplified context that trusts self-signed certs (for testing)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(5) # 5 second timeout
        raw_sock.connect(('127.0.0.1', port))

        conn = context.wrap_socket(raw_sock, server_hostname=hostname)
        
        msg = b"ping"
        conn.sendall(msg)
        
        data = conn.recv(1024)
        print(f"Received: {data.decode('utf-8', errors='ignore')}")
        
        conn.close()
        
        if b"ping" in data:
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
