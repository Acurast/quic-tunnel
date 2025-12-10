import socket
import ssl
import sys
import time
import threading

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 perf_client.py <port> <sni_hostname> <duration_sec>")
        sys.exit(1)

    port = int(sys.argv[1])
    hostname = sys.argv[2]
    duration = float(sys.argv[3])

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.connect(('127.0.0.1', port))
        conn = context.wrap_socket(raw_sock, server_hostname=hostname)
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    print(f"Connected to {hostname}:{port}. Starting benchmark for {duration}s...")

    chunk_size = 32 * 1024 # 32KB
    chunk = b'X' * chunk_size
    
    start_time = time.perf_counter()
    bytes_sent = 0
    bytes_recv = 0
    running = True
    
    def reader():
        nonlocal bytes_recv
        while running:
            try:
                data = conn.recv(32 * 1024)
                if not data: break
                bytes_recv += len(data)
            except:
                break

    t = threading.Thread(target=reader)
    t.start()

    try:
        while time.perf_counter() - start_time < duration:
            conn.sendall(chunk)
            bytes_sent += chunk_size
    except Exception as e:
        if running: print(f"Send error: {e}")
    
    end_time = time.perf_counter()
    running = False
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except:
        pass
    
    # Wait for reader to finish before closing
    t.join()
    conn.close()
    
    elapsed = end_time - start_time
    
    mb_sent = bytes_sent / (1024 * 1024)
    mb_recv = bytes_recv / (1024 * 1024)
    
    print(f"--- Results for {hostname} ---")
    print(f"Duration: {elapsed:.2f}s")
    print(f"Sent: {mb_sent:.2f} MB (throughput: {mb_sent/elapsed:.2f} MB/s)")
    print(f"Recv: {mb_recv:.2f} MB (throughput: {mb_recv/elapsed:.2f} MB/s)")

if __name__ == "__main__":
    main()
