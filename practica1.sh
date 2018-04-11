#!/bin/bash

# -------------------------------------------
# Initialize iptables and set default policy
# -------------------------------------------

# -> Delete all previous rules and set counters to 0
echo "------------------------------"
echo "-- Cleaning previous config --"
echo "------------------------------"
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z

# -> Establish the default policy
echo "------------------------------"
echo "-- Setting def policy DROP  --"
echo "------------------------------"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# -> Enable IP forwarding
echo "------------------------------"
echo "-- Enabling IP forwarding   --"
echo "------------------------------"
echo 1 > /proc/sys/net/ipv4/ip_forward

# -------------------------------------------
# Firewall interfaces
# -------------------------------------------
# -> eth2 -> 192.168.56.101/24 -> LAN
# -> eth3 ->  192.168.0.195/24 -> DMZ
# -> eth1 ->      10.0.2.16/24 -> WAN


# -------------------------------------------
# Enable NAT from LAN -> DMZ
# -------------------------------------------
iptables -t nat -A POSTROUTING -s 192.168.56.0/24 -o eth3 -d 192.168.0.193 -j MASQUERADE


# -------------------------------------------
# Allow http and ftp traffic from LAN -> DMZ
# -------------------------------------------
iptables -A FORWARD -i eth2 -s 192.168.56.0/24 -o eth3 -d 192.168.0.193 -p tcp --sport 1024:65535 --dport 20 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth2 -s 192.168.56.0/24 -o eth3 -d 192.168.0.193 -p tcp --sport 1024:65535 --dport 21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth2 -s 192.168.56.0/24 -o eth3 -d 192.168.0.193 -p tcp --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

iptables -A FORWARD -i eth3 -s 192.168.0.193 -o eth2 -d 192.168.56.0/24 -p tcp --sport 20 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth3 -s 192.168.0.193 -o eth2 -d 192.168.56.0/24 -p tcp --sport 21 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth3 -s 192.168.0.193 -o eth2 -d 192.168.56.0/24 -p tcp --sport 80 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT


# -------------------------------------------
# Allow ssh traffic from LAN -> Firewall
# -------------------------------------------
iptables -A INPUT -i eth2 -s 192.168.56.0/24 -p tcp --sport 1024:65535 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth2 -d 192.168.56.0/24 -p tcp --sport 22 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT


# -------------------------------------------
# Allow outgoing ping from Firewall -> LAN
# -------------------------------------------
iptables -A OUTPUT -o eth2 -d 192.168.56.0/24 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i eth2 -s 192.168.56.0/24 -p icmp --icmp-type echo-reply -j ACCEPT


# -------------------------------------------
# Allow outgoing ping from Firewall -> DMZ
# -------------------------------------------
iptables -A OUTPUT -o eth3 -d 192.168.0.193 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i eth3 -s 192.168.0.193 -p icmp --icmp-type echo-reply -j ACCEPT


# -------------------------------------------
# Enable NAT from LAN -> INET
# -------------------------------------------
#iptables -t nat -A POSTROUTING -s 192.168.56.0/24 -o eth1 -d 0.0.0.0/0 -j SNAT --to 10.0.2.16




#iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.0.193 -j ACCEPT
#iptables -A FORWARD -s 192.168.0.193 -d 192.168.56.0/24 -j ACCEPT




# -------------------------------------------
# Enable port NAT from Inet to DMZ for ftp and http server
# -------------------------------------------
#iptables -t nat -A PREROUTING -i eth1 -s 0.0.0.0/0 -p tcp --dport 20 -j DNAT --to 192.168.0.193
#iptables -t nat -A PREROUTING -i eth1 -s 0.0.0.0/0 -p tcp --dport 21 -j DNAT --to 192.168.0.193
#iptables -t nat -A PREROUTING -i eth1 -s 0.0.0.0/0 -p tcp --dport 80 -j DNAT --to 192.168.0.193


# -------------------------------------------
# Enable logging for dropped packets
# -------------------------------------------
echo "------------------------------"
echo "-- Enable log drop packets  --"
echo "------------------------------"
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A FORWARD -j LOGGING
iptables -A OUTPUT -j LOGGING

iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A LOGGING -j DROP


# -------------------------------------------
# Save configuration
# -------------------------------------------
echo "------------------------------"
echo "-- Saving iptables config   --"
echo "------------------------------"
echo "service iptables save"
service iptables save

echo "------------------------------"
echo "--          FINISH!         --"
echo "------------------------------"
