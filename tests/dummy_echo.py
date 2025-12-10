import socket
import sys
import threading

def handle(conn):
    try:
        while True:
            data = conn.recv(32768)
            if not data: break
            conn.sendall(data)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()

def main():
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(5)
    print(f"Dummy echo server listening on {port}")
    sys.stdout.flush()
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,)).start()

if __name__ == '__main__':
    main()
