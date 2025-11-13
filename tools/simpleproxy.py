#!/usr/bin/env python3
import socket
import threading
import argparse


def build_proxy_header(client_sock):
    """
    Build a PROXY protocol v1 header based on the client connection.
    Format:
      PROXY TCP4/TCP6 <client_ip> <dest_ip> <client_port> <dest_port>\r\n
    """
    try:
        client_ip, client_port = client_sock.getpeername()
        local_ip, local_port = client_sock.getsockname()
    except OSError:
        # Fall back to UNKNOWN if we can't get addresses
        return b"PROXY UNKNOWN\r\n"

    family = client_sock.family
    if family == socket.AF_INET:
        proto = "TCP4"
    elif family == socket.AF_INET6:
        proto = "TCP6"
        # strip scope id if present in ip string (e.g. "fe80::1%eth0")
        if "%" in client_ip:
            client_ip = client_ip.split("%", 1)[0]
        if "%" in local_ip:
            local_ip = local_ip.split("%", 1)[0]
    else:
        return b"PROXY UNKNOWN\r\n"

    header = f"PROXY {proto} {client_ip} {local_ip} {client_port} {local_port}\r\n"
    return header.encode("ascii")


def pipe(src, dst):
    """
    Copy bytes from src to dst until EOF or error.
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            src.shutdown(socket.SHUT_RD)
        except OSError:
            pass


def handle_client(client_sock, backend_addr):
    backend_sock = None
    try:
        backend_sock = socket.create_connection(backend_addr)

        # Send PROXY header first
        header = build_proxy_header(client_sock)
        backend_sock.sendall(header)

        # Start bidirectional piping
        t1 = threading.Thread(target=pipe, args=(client_sock, backend_sock), daemon=True)
        t2 = threading.Thread(target=pipe, args=(backend_sock, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    finally:
        if backend_sock is not None:
            backend_sock.close()
        client_sock.close()


def run_proxy(listen_host, listen_port, backend_host, backend_port):
    backend_addr = (backend_host, backend_port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_host, listen_port))
        server.listen()
        print(f"Listening on {listen_host}:{listen_port}, forwarding to {backend_host}:{backend_port}")

        while True:
            client_sock, addr = server.accept()
            print(f"New connection from {addr}")
            t = threading.Thread(target=handle_client, args=(client_sock, backend_addr), daemon=True)
            t.start()


def main():
    parser = argparse.ArgumentParser(
        description="Simple reverse proxy that prepends a PROXY protocol v1 header."
    )
    parser.add_argument("backend_host", help="Backend host to proxy to")
    parser.add_argument("backend_port", type=int, help="Backend port to proxy to")
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Host/interface to listen on (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)",
    )
    args = parser.parse_args()

    run_proxy(args.listen_host, args.listen_port, args.backend_host, args.backend_port)


if __name__ == "__main__":
    main()
