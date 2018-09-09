# tsam_ps
Project 1 - TSAM - Fall 2018

## The scanner 
The main scanner is a syn-ack scanner.
```make scan```
```sudo ./scan <source_ip> <ip_range.txt>```

It scans the ip range provided as the second argument from the source ip provided as the first argument
All the host ip's in the provided file are scanned randomly and each port for each host is also scanned randomly.
The scan spawns up to a a hundred threads that all scan one host at a time until all hosts have been scanned.

Each thread sleeps a random amount of time from 0.5 to 0.7 seconds after each scan.

## The Code

The scan.cpp/h spawns threads to scan the ip range given. Each thread picks a random host and starts to scan. 
For each host to scan, a syn scan object is created that has is own pool of ports to scan. The syn object then scans one port, sleeps for a random amount of time from 0.5 - 0.7 seconds and then scans the next port. All ports scanned are in random order between runs. Thus all hosts and ports are scanned in random order.

When a thread has finished scanning a host, another host is picked if more hosts need to be scanned, else the thread joins with the main thread.


The syn.cpp is a syn-ack scanner that has a bunch of ports that are commonly open and vulnerable. It creates headers, a datagram, a receive buffer and other structures needed for each port to scan. It's main method is the scan method which scans a provided port.


scan_utilities.ccp/h is a utility namespace that provides various of methods to encapsulate work for scanner objects. The idea was to implement more scan methods so they could all use this utility namespace but we ran out of time.

connect-scan.cpp is a simple full 3way handshake connect scan that is slow and does not use threading.

We know that some more refactoring could be made and specially on the connect-scan and scan_utilities files. However we were just to scared to accidentally break something in the end so we hope that you find it in your hearts to forgive.

## Collaboration and help from the internet

We did not collaborate with anyone in that sense. We did however spend an hour or so with one group (group 38). We were working on a way to parse the recieve buffer used in recv(). We had a blast turning arount all the big endian bytes to little endian to check the flags. It was really funky how often the result would be correct if we did not turn the bytes arount but just accessed the flags through the tcphdr struct we casted the recieve buffer to. But in the end we did not want to gamble on such whichcraft so we agreed that using ntohs() on the bytes for the flags and just a simple bitwise AND to get the result was the right way to go.

We had some help with structuring the TCP and IP headers along with the pseudo header from https://binarytides.com/raw-sockets-c-code-linux, we took the checksum function straight from that code because we knew that it is a generic algorithm. We also spent some time on reading about the reasons for the pseadu header and other stuff to be sure that we understood what we were doing.

But just overall, we spent a fair amount of hours on this project because we did not want to much help and we wanted to understand as much as possible. I would assume that the hours spend were just about TIME_LIMIT_EXCEEDED