# CS 331 Assignment 1

## Team:
- Jaskirat Singh Maskeen (23110146)
- Karan Sagar Gandhi (23110157)

## Report @ [`./Report/report.pdf`](./Report/report.pdf)

## Task 1

How to run ?

```sh
C:\Users\Me\Assignment_1>cd  "Task 1"

C:\Users\Me\Assignment_1\Task 1>make
Starting server in a new cmd window...
Waiting 2 seconds then starting client in a new cmd window...
```

If you want to run client and server separatey:


```sh
C:\Users\Me\Assignment_1\Task 1>client.py -h
usage: client.py [-h] --pcap PCAP [--server SERVER] [--port PORT] [--sleep_seconds SLEEP_SECONDS]

options:
  -h, --help            show this help message and exit
  --pcap PCAP           input pcap file
  --server SERVER       server IP
  --port PORT           server port
  --sleep_seconds SLEEP_SECONDS
                        maximum number of seconds to sleep before sending each dns request

C:\Users\Me\Assignment_1\Task 1>server.py -h
usage: server.py [-h] [--host HOST] [--port PORT] --rules RULES

options:
  -h, --help     show this help message and exit
  --host HOST    server host
  --port PORT    server port
  --rules RULES  rules file for DNS resolution
```


Flow summarised:

1. Filter the DNS query packets from the PCAP.
    - So, figure out the syntax of the DNS packets
    - [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt), Section 4.
2. Add custom header and send to server over UDP.
3. Server recieves, parses the custom header to decide the ip pool. 
4. Server parses the DNS query to extract the domain.
5. Server sends the domain, and the resolved ip back to client via UDP.
6. Client artifically sleeps for few seconds to simulate, time difference between two DNS queries.

![](./Task%201/output.png)