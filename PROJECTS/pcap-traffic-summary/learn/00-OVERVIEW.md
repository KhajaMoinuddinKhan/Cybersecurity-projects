# Overview

A packet capture is a recording, and a recording is only useful once somebody has described it. This project is that description: it reads a PCAP file and answers the questions an analyst actually opens a capture to ask. How long was this? How much moved? Which addresses and ports carried the most? Who was talking to whom? Which names were resolved?

The tool is deliberately a reader. It never opens a network interface, never generates traffic, and never downloads a sample for you. Everything it reports came out of the file you handed it, which is the property that makes its output defensible.

## What you get

Five sections, each answering a different question. The protocol totals tell you the shape of the traffic. The byte totals tell you the weight of it. The source-host ranking, ordered by bytes, tells you who was heavy rather than who was merely chatty. The flow ranking groups packets into five-tuples so you can see conversations rather than a list of unrelated addresses. The DNS section gives you names, which are usually the fastest way to make a capture mean something.

## What it is not

It is not an intrusion detector, and it has no opinion about whether traffic is good or bad. A host that appears at the top of the byte ranking may be a backup server doing its job or an exfiltration in progress, and the capture cannot tell you which. It does not inspect payloads, does not reassemble streams, and cannot see anything that was encrypted or that the capture never recorded.

## A useful first exercise

Build a capture with one DNS question and its reply, then read the summary. You will see two packets and one query, which is the first place people learn that a packet count and an application-level event are different things. Add a TCP connection and watch its destination port appear as its own line. Then add a second, much larger transfer and check that the byte ranking moves the heavy host to the top while the packet ranking stays where it was. That contrast is the reason both columns exist.

[Back to the project guide](../README.md)
