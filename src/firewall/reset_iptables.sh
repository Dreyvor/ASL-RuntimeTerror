#!/bin/bash
/usr/sbin/iptables -F
/usr/sbin/iptables -t mangle -F
/usr/sbin/iptables -t port-scanning -F
/usr/sbin/iptables -X
/usr/sbin/iptables -P INPUT ACCEPT 
/usr/sbin/iptables -P FORWARD ACCEPT 
/usr/sbin/iptables -P OUTPUT ACCEPT
/usr/sbin/iptables -L -n -v


chmod u+x /home/firewall/firewall_iptables.sh