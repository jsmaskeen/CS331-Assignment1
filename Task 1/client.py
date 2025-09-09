import argparse
import dpkt
import socket
from datetime import datetime
from prettytable import PrettyTable
from helpers import is_dns, default_port
from rich import print
from rich.markup import escape
from time import sleep
from random import random

# # process a pcap file, extract DNS queries (UDP port 53),
# # and send them to the custom DNS server with an added custom header.
def process_pcap(pcap_path, server_host, server_port, sleep_seconds):
    queries = []
    # single UDP socket for all queries
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        i = 0  # counter for generating 2-digit sequence IDs
        for ts, buf in pcap:
            # Parse Ethernet frame
            try:
                eth = dpkt.ethernet.Ethernet(buf)  # LAYER 2
            except Exception:
                continue
            ip = eth.data  # LAYER 3

            # skip non-IPv4 packets
            if not isinstance(ip, dpkt.ip.IP):
                continue
            udp = ip.data  # LAYER 4
            if not isinstance(udp, dpkt.udp.UDP):
                continue
            # only process DNS queries (port 53)
            if udp.dport != 53:
                continue

            # check if the packet is DNS packet
            if is_dns(udp.data):
                # artificially sleep to simulate the actual delay between two dns calls, as we skip non DNS packets
                if sleep_seconds != 0:
                    sleep_val = random() * sleep_seconds
                    print(
                        f"[green]{escape('[client]')}[/green] artificially sleeping for {sleep_val:.3f}s."
                    )
                    sleep(sleep_val)
                    print(f"[green]{escape('[client]')}[/green] awake now!")

                seq_id = i % 100
                header = datetime.now().strftime("%H%M%S") + f"{seq_id:02d}"
                header = header.ljust(8, "0")

                # prepare payload
                payload = header.encode("ascii") + udp.data

                udp_socket.sendto(payload, (server_host, server_port))

                # recieve response
                try:
                    # timeout to avoid waiting forever
                    udp_socket.settimeout(8.0)
                    response_bytes, _ = udp_socket.recvfrom(4096)
                except socket.timeout:
                    print(
                        f"[green]{escape('[client]')}[/green] server did not respond in time"
                    )
                    continue
                except Exception as e:
                    print(f"[green]{escape('[client]')}[/green] an error occurred: {e}")
                    break

                # parse JSON response from server
                try:
                    resp = json.loads(response_bytes.decode("utf-8"))
                except Exception:
                    resp = {
                        "header": header,
                        "domain": "error_in_parsing",
                        "ip": "error_in_parsing",
                    }

                custom_header = resp.get("header", header)
                domain = resp.get("domain", "<unknown>")
                ip = resp.get("ip", "<unknown>")
                queries.append((custom_header, domain, ip))
                print(
                    f"[green]{escape('[client]')}[/green] {custom_header} {domain} resolved to {ip}"
                )
                i += 1  # increment sequence ID for next query

    udp_socket.close()  # CLOse the socket
    return queries


def main(pcap, server_host, server_port, sleep_seconds):
    queries = process_pcap(pcap, server_host, server_port, sleep_seconds)
    table = PrettyTable(["Custom Header", "Domain", "Resolved IP Address"])

    # Add results to table
    for custom_header, domain, ip in queries:
        table.add_row([custom_header, domain, ip])

    print(table)


import json

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, help="input pcap file")
    parser.add_argument("--server", default="127.0.0.1", help="server IP")
    parser.add_argument("--port", type=int, default=default_port, help="server port")
    parser.add_argument(
        "--sleep_seconds",
        type=int,
        default=2,
        help="maximum number of seconds to sleep before sending each dns request",
    )
    args = parser.parse_args()
    main(args.pcap, args.server, args.port, args.sleep_seconds)
