# CS 331 Assignment 1

## Team:
- Jaskirat Singh Maskeen (23110146)
- Karan Sagar Gandhi (23110157)

## Task 1

How to run ?

```sh
C:\Users\Me\Assignment_1>cd  "Task 1"

C:\Users\Me\Assignment_1\Task 1>make
Starting server in a new cmd window...
Waiting 2 seconds then starting client in a new cmd window...

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

<!-- 
DNS message:

header 12 bytes

ID      (2 bytes)
Flags   (2 bytes)
QDCOUNT (2 bytes)  # # of questions
ANCOUNT (2 bytes)  # # of answers
NSCOUNT (2 bytes)  # # of authority records
ARCOUNT (2 bytes)  # # of additional records

Question section (variable length):

QNAME: domain name (labels, length-prefixed, terminated by 0)

QTYPE: 2 bytes

QCLASS: 2 bytes

Answer / Authority / Additional sections (variable length, same basic structure as Resource Records).


[4-byte length prefix][payload of that length]

-->