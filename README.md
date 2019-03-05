## Project:

A novel interactive IDS(Intrusion detection system)

## Statement:

Since the number of network users increases dramatically, the
network security becomes more and more important. But most of
the time users do not have a suitable tool to identify the
content of the network traffic and hence may not detect the
current network is harmful or not properly. Then people
implement IDS and hope to solve this kind of problem. However,
sometimes the traditional IDS may not detects andalerts the
intrusion correctly. As a result, I intend to invent a
novel interactive IDS to solve this kind of problem.

## Goal:

My goal is to implement an interactive IDS which monitoring
and report current traffic packets to users then let users to
decide the traffic packet is harmful to us or not. After user
know what happens about the traffic, then allow or disallow
such kind of traffic packet incoming or outgoing. While such
mechanism may let malicious things came in and executed at the
first time, it can let users have a direct perception and know
what is going on then would not make such thing happen in the
second time. After that, the users can set their configuration
file more properly. And such thing actually is good for users
since not all of the users are the expert of computer science
or cybersecurity, and most of the time the malicious packets
cannot actually do bad thing to our computer because of the IPS
(Intrusion prevention systems).

## Implement:

I use C language to implement that. Basically, I use the pcap
library to capture current traffic packets and use the iptc
library to allow or disallow the packets go through.

## Functional Feature:
1. Extract the information from packets, e.g. source and
destination IP address, MAC address, protocol,
port number, etc.

2. Allow or disallow the traffic packets based on users
response.

3. Skip the packets which already added in the rules table.

4. Enable load rules via file before sniffing the traffic.

## Security Feature:

1. When a new rule added to the rules table, also restrict the
rate of matches to prevent the DDoS attack. Since although we
may make rules to allow the outcoming traffic comes in, it may
a good traffic packet pair, but sometime the attack can use
such rules which accepted by the host to perform DDoS attack.
As a result, we add such restriction to avoid such thing
happen.

2. Check the user response/input before running it in order to
avoid error we do not hope, e.g. the buffer overflow, code
injection, etc.

3. Only the privileged user can monitor and modify the rule
table.

## The Integrity:

1. Check the user response in case of preventing the un-except
error happen such as corruption or unauthorized access e.g.
the buffer overflow, code injection, etc.

2. Upload the configuration file before sniffing every time.
Of course, I can check the rule in the iptable to determine
these rules are uploaded or not, but the rules or the contents
of iptables may change during the program check the rules
exist in the iptables or not. In order to avoid such situations
which similar to race condition happen, the program loaded the
configuration every time.

3. If the configuration file not exist, we create a file with
permission which the only root user can write the file.

4. Use exec(3) to execute the commands of configuration file
instead of system(3), popen(3), etc. Since the tools like
system(3), popen(3) can be hijacked.

5. When use exec(3) execute the commands, explicitly gives the
path of iptables instead of calling it implicitly, which the
later action can be exploited.

## The Authentication:

1. Since the this IDS can modify the rule table, we confirm
the identity of data author and only allow root user can
manipulate such of thing.

2. If the configuration file exists, we check the file has
related restrict or not. If not, we would not execute the
command of the file, and also remove the file then create a
new configuration file with limited permission.

## Evaluation:

1. Captures the network traffic which we want to.
2. Add the rules with user expectation.
3. Disallow the code injection with user response.
4. Disallow insufficient privilege user to modify the
configuration file.

## Limitation:

Unfortunately, this IDS need to work combine with the IPS,
and let IPS filter most of the malicious traffic and after
that IDS can monitor the filtered packets
and find the potential malicious traffic packets.

## Future Work:

Instead of just monitoring the traffic, I use the sockets
instead of pcap to manipulate the packets, which in such
situation the users can manipulate the packets at the first
time. However, maybe user may not make a decision since they
only know some static information rather than dynamic
information. So I need to combine these
two mechanisms and let them works properly.

## Refer:

1. https://wemakeappsgo.f5.com/security/how-to-ensure-the-availability-integrity-and-confidentiality-of-your-apps/
2. https://searchsecurity.techtarget.com/definition/intrusion-detection-system
3. Slides in the lecture.

## How to run:
```
	$ sudo su
	# make
	# ./ids
```
Use Ctrl + C to stop it.

# Require:
iptables packet
pcap packet

