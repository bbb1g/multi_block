#!/bin/sh

iptables -F
iptables -A OUTPUT -p tcp -j NFQUEUE
iptables -A INPUT -p tcp -j NFQUEUE
python multi_block.py
