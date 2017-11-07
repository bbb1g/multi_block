#!/usr/bin/python

from pwn import u64
from hashlib import sha256

if __name__=="__main__":
    hosts = open("top-1m.csv").read().split("\n")
    table = []

    for host in hosts:
        h = host.split(",")
        if len(h) < 2:continue
        table.append(u64(sha256(h[1]).digest()[:8]))

    open("toBlock_hashtable","w").write(str(table))
