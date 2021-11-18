#!/bin/bash

# TODO: Add ip forwarding in this script directly

##### Start by resetting every rules with a standard blacklist #####

### IPv4 ###
/usr/sbin/iptables -P INPUT DROP
/usr/sbin/iptables -P FORWARD DROP
/usr/sbin/iptables -P OUTPUT DROP

# Drop old rules
/usr/sbin/iptables -F
/usr/sbin/iptables -t mangle -F

### IPv6 ###
# Drop everything for IPv6
/usr/sbin/ip6tables -t mangle -P PREROUTING DROP
/usr/sbin/ip6tables -P INPUT DROP
/usr/sbin/ip6tables -P FORWARD DROP
/usr/sbin/ip6tables -P OUTPUT DROP

# Drop old rules
/usr/sbin/ip6tables -F
/usr/sbin/ip6tables -t mangle -F

### ACCEPT Normal traffic ###
# User - web server
/usr/sbin/iptables -A FORWARD -i enp0s10 -o enp0s9 -p tcp -d 192.168.20.10 -dport 443 -j ACCEPT
/usr/sbin/iptables -A FORWARD -i enp0s9 -o enp0s10 -p tcp -s 192.168.20.10 -sport 443 -j ACCEPT

# web server - core CA
/usr/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 192.168.20.10 -d 192.168.10.10 -dport 8080 -j ACCEPT
/usr/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 192.168.10.10 -sport 8080 -d 192.168.20.10 -j ACCEPT

# web server - database
/usr/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 192.168.20.10 -d 192.168.10.30 -dport 3306 -j ACCEPT
/usr/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 192.168.10.30 -sport 3306 -d 192.168.20.10 -j ACCEPT

# web server - backup
/usr/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 192.168.20.10 -d 192.168.10.20 -dport 8888 -j ACCEPT
/usr/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 192.168.10.20 -sport 8888 -d 192.168.20.10 -j ACCEPT

### ACCEPT SSH admin traffic ###
# web server
/usr/sbin/iptables -A FORWARD -i enp0s10 -o enp0s9 -p tcp -d 192.168.20.10 -dport ssh -j ACCEPT
/usr/sbin/iptables -A FORWARD -i enp0s9 -o enp0s10 -p tcp -s 192.168.20.10 -sport ssh -j ACCEPT

# Internal network
/usr/sbin/iptables -A FORWARD -i enp0s10 -o enp0s8 -p tcp -d 192.168.10.0/24 -dport ssh -j ACCEPT
/usr/sbin/iptables -A FORWARD -i enp0s8 -o enp0s10 -p tcp -s 192.168.10.0/24 -sport ssh -j ACCEPT

# Firewall administration and configuration
/usr/sbin/iptables -A INPUT -i enp0s10 -p tcp -d 42.42.42.1 -dport ssh -j ACCEPT
/usr/sbin/iptables -A INPUT -i lo -j ACCEPT

##### DDOS protection for the outside world #####
# Thanks to https://javapipe.com/blog/iptables-ddos-protection/ and https://gist.github.com/jamesbrink/c78281f326f667f1137b3c3d9f9940b1

### 1. Drop invalid packets ###
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -m conntrack --ctstate INVALID -j DROP

### 2. Block new packets that are not SYN ###
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

### 3. Block Uncommon MSS Values ###
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

### 4. Block Packets With Bogus TCP Flags ###
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags FIN,ACK FIN -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ACK,URG URG -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ACK,FIN FIN -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ACK,PSH PSH -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ALL ALL -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ALL NONE -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP  

### 5. Block spoofed packets ### 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -s 192.168.0.0/16 -j DROP 
/usr/sbin/iptables -t mangle -A PREROUTING -i enp0s10 -s 0.0.0.0/8 -j DROP
/usr/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  

### 6. Drop ICMP (you usually don't need this protocol) ### 
/usr/sbin/iptables -t mangle -A PREROUTING -p icmp -j DROP

### 7. Drop fragments in all chains ### 
/usr/sbin/iptables -t mangle -A PREROUTING -f -j DROP

### 8. Limit connections per source IP ### 
/usr/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  

### 9. Limit RST packets ### 
/usr/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
/usr/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP 

### 10. Limit new TCP connections per second per source IP ### 
/usr/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
/usr/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  

### SSH brute-force protection ### 
/usr/sbin/iptables -A TCP -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
/usr/sbin/iptables -A TCP -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

### Protection against port scanning ###
/usr/sbin/iptables -N port-scanning
/usr/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
/usr/sbin/iptables -A port-scanning -j DROP