import argparse
import socket
import struct
import json
from helpers import recieve_n_bytes, DNSPacket, default_port
from rich import print
from rich.markup import escape

# Given pool of available IP addresses for load balancing
IP_Pool = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4",
    "192.168.1.5",
    "192.168.1.6",
    "192.168.1.7",
    "192.168.1.8",
    "192.168.1.9",
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.14",
    "192.168.1.15",
]

# load rules from json file
def load_rules(path):
    with open(path, "r") as f:
        return json.load(f)

# get the first 8 custom header, and dns message
def split_custom_header_and_dns(msg):
    if len(msg) < 8:
        raise ValueError("message shorter than 8 bytes")
    header = msg[:8].decode("ascii", errors="replace")
    dns_bytes = msg[8:]
    return header, dns_bytes


# parse the custom header to extract ip address from rules. Ref:
# https://docs.google.com/document/d/1HZYk8UXO_sGSfocGJV0dZ5UPLo_cB9qtdXRbdwxOMr8/edit?usp=sharing
def get_ip_from_rules(header, rules):
    # header format "HHMMSSID" -> hour = header[:2], id = header[6:8]
    hour = int(header[0:2])
    _id = int(header[6:8])

    time_based_routing = rules["timestamp_rules"]["time_based_routing"]
    # Determine which slot: morning/afternoon/night
    period = None
    if 4 <= hour <= 11:
        period = "morning"
    elif 12 <= hour <= 19:
        period = "afternoon"
    else:
        period = "night"
    
    period_routing = time_based_routing[period]
    mod = int(period_routing["hash_mod"])

    idx = ((_id % mod) + int(period_routing["ip_pool_start"])) % len(IP_Pool)
    return IP_Pool[idx]

# serve a single tcp client
def serve_client(conn, addr, rules):
    print(f"[red]{escape('[server]')}[/red] connection from {addr}")
    try:
        while True:
            # read 4-byte length prefix 
            _len = recieve_n_bytes(conn, 4)
            if not _len:
                print(f"[red]{escape('[server]')}[/red] connection closed by client")
                break
            (length,) = struct.unpack("!I", _len)
            
            # read message payload of prefix length
            payload = recieve_n_bytes(conn, length)
            if payload is None:
                print(f"[red]{escape('[server]')}[/red] incomplete payload")
                break
            try:
                header, dns_bytes = split_custom_header_and_dns(payload)
                domain = DNSPacket(dns_bytes).get_domain()
                resolved_ip = get_ip_from_rules(header, rules)
                resp = {"header": header, "domain": domain, "ip": resolved_ip}
            except Exception as e:
                resp = {
                    "header": "ERR00000",
                    "domain": "error",
                    "ip": "0.0.0.0",
                    "error": str(e),
                }
            resp_bytes = json.dumps(resp).encode("utf-8")
            conn.sendall(struct.pack("!I", len(resp_bytes)) + resp_bytes)
            print(
                f"[red]{escape('[server]')}[/red] processed header={resp['header']} domain={resp['domain']} ip={resp['ip']}"
            )
    finally:
        conn.close()
        print(f"[red]{escape('[server]')}[/red] closed {addr}")


def run(host, port, rules_path):
    rules = load_rules(rules_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[red]{escape('[server]')}[/red] listening on {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            # handle one client at a time in same process
            serve_client(conn, addr, rules)
    except KeyboardInterrupt:
        print(f"[red]{escape('[server]')}[/red] exiting")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
    )
    parser.add_argument("--rules", required=True, default="rules.json")
    args = parser.parse_args()
    run(args.host, args.port, args.rules)
