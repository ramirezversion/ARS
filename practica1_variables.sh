#!/bin/bash

clear

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
echo "-- Setting def policy: DROP --"
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

# -> Variable declaration
IFACE_LAN="eth2"
IFACE_DMZ="eth3"
IFACE_WAN="eth1"

NETWK_LAN="192.168.56.0/24"
NETWK_DMZ="192.168.0.0/24"
NETWK_WAN="10.0.2.0/24"

IP_DMZ_SERVER="192.168.0.193"
IP_WAN_INET="0.0.0.0/0"


echo "------------------------------"
echo "-- Starting configuration   --"
echo "------------------------------"


# -------------------------------------------
# Enable NAT from LAN -> DMZ
# -------------------------------------------
iptables -t nat -A POSTROUTING -s $NETWK_LAN -o $IFACE_DMZ -d $IP_DMZ_SERVER -j MASQUERADE


# -------------------------------------------
# Allow http and ftp traffic from LAN -> DMZ
# -------------------------------------------
iptables -A FORWARD -i $IFACE_LAN -s $NETWK_LAN -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 20 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $IFACE_LAN -s $NETWK_LAN -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $IFACE_LAN -s $NETWK_LAN -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 20 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 21 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 80 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT

# -------------------------------------------
# Allow ftp pasv traffic from LAN -> DMZ
# -------------------------------------------
# pasv_enable=YES
# pasv_min_port=10090
# pasv_max_port=10100
iptables -A FORWARD -i $IFACE_LAN -s $NETWK_LAN -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 10090:10100 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 10090:10100 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT

# -------------------------------------------
# Allow ssh traffic from LAN -> Firewall
# -------------------------------------------
iptables -A INPUT -i $IFACE_LAN -s $NETWK_LAN -p tcp --sport 1024:65535 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 22 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT


# -------------------------------------------
# Allow outgoing ping from Firewall -> LAN
# -------------------------------------------
iptables -A OUTPUT -o $IFACE_LAN -d $NETWK_LAN -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i $IFACE_LAN -s $NETWK_LAN -p icmp --icmp-type echo-reply -j ACCEPT


# -------------------------------------------
# Allow outgoing ping from Firewall -> DMZ
# -------------------------------------------
iptables -A OUTPUT -o $IFACE_DMZ -d $IP_DMZ_SERVER -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i $IFACE_DMZ -s $IP_DMZ_SERVER -p icmp --icmp-type echo-reply -j ACCEPT


# -------------------------------------------
# Enable nat from LAN -> INET
# -------------------------------------------
iptables -t nat -A POSTROUTING -s $NETWK_LAN -o eth1 -d $IP_WAN_INET -j SNAT --to 10.0.2.16


# -------------------------------------------
# Enable http traffic from LAN -> INET
# for real navigation it will be necessary DNS traffic from our DNS server (TCP) or clients (UDP) to an external DNS server. This configuration has been omitted.
# -------------------------------------------
iptables -A FORWARD -i $IFACE_LAN -s $NETWK_LAN -o eth1 -d $IP_WAN_INET -p tcp --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -s $IP_WAN_INET -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 80 --dport 1024:65535 -m state --state ESTABLISHED  -j ACCEPT


# -------------------------------------------
# Enable ssh traffic from LAN -> INET
# -------------------------------------------
iptables -A FORWARD -i $IFACE_LAN -s $NETWK_LAN -o eth1 -d $IP_WAN_INET -p tcp --sport 1024:65535 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -s $IP_WAN_INET -o $IFACE_LAN -d $NETWK_LAN -p tcp --sport 22 --dport 1024:65535 -m state --state ESTABLISHED  -j ACCEPT


# -------------------------------------------
# Enable port nat for incoming http and ftp traffic from INET -> DMZ
# -------------------------------------------
iptables -t nat -A PREROUTING -i eth1 -s $IP_WAN_INET -p tcp --dport 20 -j DNAT --to $IP_DMZ_SERVER:20
iptables -t nat -A PREROUTING -i eth1 -s $IP_WAN_INET -p tcp --dport 21 -j DNAT --to $IP_DMZ_SERVER:21
iptables -t nat -A PREROUTING -i eth1 -s $IP_WAN_INET -p tcp --dport 80 -j DNAT --to $IP_DMZ_SERVER:80


# -------------------------------------------
# Enable http and ftp traffic from INET -> DMZ
# -------------------------------------------
iptables -A FORWARD -i eth1 -s $IP_WAN_INET -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 20 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -s $IP_WAN_INET -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -s $IP_WAN_INET -o $IFACE_DMZ -d $IP_DMZ_SERVER -p tcp --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o eth1 -d $IP_WAN_INET -p tcp --sport 20 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o eth1 -d $IP_WAN_INET -p tcp --sport 21 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $IFACE_DMZ -s $IP_DMZ_SERVER -o eth1 -d $IP_WAN_INET -p tcp --sport 80 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT


# -------------------------------------------
# Enable nat from DMZ -> INET
# -------------------------------------------
iptables -t nat -A POSTROUTING -s $IP_DMZ_SERVER -o eth1 -d $IP_WAN_INET -j SNAT --to 10.0.2.16


# -------------------------------------------
# Enable logging for dropped packets
# -------------------------------------------
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
service iptables save

echo "------------------------------"
echo "--          FINISH!         --"
echo "------------------------------"
