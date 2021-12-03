# Project: ICMP Intrusion Detection System

## About
The threat model is an ICMP Ping Flood attack. It is a Denial of Service attack where the attacker floods the victim device with ICMP Type 8 Echo (Ping) requests. The target device will subsequently respond with an equal number of reply packets. This can potentially saturate bandwidth and cause denial of service, preventing legitimate packets from going through.

My project is an Intrusion Detection System. It reads in packets from a .pcap file (file that contains packet data from a network), filters the ICMP packets, and logs important information about them in a log file. The user examines the log. If the log shows many Echo (Ping) requests (Type 8) sent within a short time frame, the user may be under a Ping Flood attack.

When the user views the log and finds that they are under a ICMP Ping Flood attack, they can take action on the malicious IP addresses and networks such as blocking IP addresses. The IDS saves the admin valuable time and resources by filtering out the ICMP packets which can help them quickly identify and stop a potentially malicious ICMP Ping Flood attack before it gets out of hand. 

## Instructions
1. Compile c program with the -lpcap flag

```gcc main.c -lpcap```

2. Run with pcap file as an argument:

```./a.out [pcap filename]```

[This website](https://kb.mazebolt.com/knowledgebase/icmp-ping-flood/) has a pcap file with a simulated ICMP Ping Flood attack which you can download (at the bottom).

3. View log.txt.   
