import argparse
import socket
import json
from helpers import DNSPacket, default_port
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
    minute = int(header[2:4])
    _id = int(header[6:8])

    time_based_routing = rules["timestamp_rules"]["time_based_routing"]
    # Determine which slot: morning/afternoon/night
    for key, value in time_based_routing.items():
        start, end = value["time_range"].split("-")
        start_h, start_m = map(int, start.split(":"))
        end_h, end_m = map(int, end.split(":"))
        start_total = start_h * 60 + start_m
        end_total = end_h * 60 + end_m
        current_total = hour * 60 + minute

        if end_total < start_total:  # time range crosses midnight
            end_total += 24 * 60

        if start_total <= current_total <= end_total or start_total <= current_total + 24 * 60 <= end_total:
            period = key
            break

    assert period is not None, "Could not determine time period from header"
    
    period_routing = time_based_routing[period]
    mod = int(period_routing["hash_mod"])

    idx = ((_id % mod) + int(period_routing["ip_pool_start"])) % len(IP_Pool)
    return IP_Pool[idx]


def populate_dns_frame(dns_bytes, ip) -> bytes:
    # first 12 bytes = header
    # make answer section = 1 in the header
    if len(dns_bytes) < 12:
        raise ValueError("Too short to be DNS packet")

    dns_packet = DNSPacket(dns_bytes)
    dns_packet.append_resolved_ip(ip)
    return dns_packet.data


def run(host, port, rules_path):
    rules = load_rules(rules_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # use UDP
    sock.bind((host, port))
    print(f"[red]{escape('[server]')}[/red] listening on {host}:{port}")
    try:
        while True:
            # receive data and client address
            payload, addr = sock.recvfrom(4096)
            print(f"[red]{escape('[server]')}[/red] connection from {addr}")
            
            try:
                header, dns_bytes = split_custom_header_and_dns(payload)
                domain = DNSPacket(dns_bytes).get_domain()
                resolved_ip = get_ip_from_rules(header, rules)
                resp = populate_dns_frame(dns_bytes, resolved_ip)
            except Exception:
                continue
                        
            sock.sendto(header.encode("ascii") + resp, addr)
            print(
                f"[red]{escape('[server]')}[/red] processed header={header} domain={domain} ip={resolved_ip}"
            )
    except KeyboardInterrupt:
        print(f"[red]{escape('[server]')}[/red] exiting")
    finally:
        sock.close()



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0",help="server host")
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,help="server port"
    )
    parser.add_argument("--rules", required=True, default="rules.json",help="rules file for DNS resolution")
    args = parser.parse_args()
    run(args.host, args.port, args.rules)
