#!/usr/bin/python

from netfilterqueue import NetfilterQueue
from pwn import u64
from hashlib import sha256
import os

TYPETCP=6
print "Loading Block Table..."
blockTable = eval(open("toBlock_hashtable").read())
print "Completely Loaded!!"
print "Table Length : "+str(len(blockTable))

def getHost(data):
    if (not data.startswith("GET")) and \
       (not data.startswith("POST")) and \
       (not data.startswith("HEAD")) and \
       (not data.startswith("DELETE")) and \
       (not data.startswith("PUT")) and \
       (not data.startswith("OPTIONS")):
           return 0         #check if packet is HTTP protocol
    #print "YOYO"
    hostOffset = data.find("Host: ")
    if not hostOffset:
        return 0            #something wrong
    hostOffset += 6
    domain = data[hostOffset:].split("\r\n")[0]
    print domain
    return domain

def check(value):   #Binary Search
    first=0
    last=len(blockTable)-1
    mid=0

    while (first <= last):
        mid = (first+last)/2
        if blockTable[mid] == value:
            return mid
        else:
            if blockTable[mid] > value:
                last = mid-1
            else:
                first = mid+1

    return -1

def hostCheck(payload):
    protocalIdentifier = ord(payload[9])
    if protocalIdentifier != TYPETCP:   #check if packet is TCP
	print "NOT TCP PROTOCAL!"
        return 1
    #print "ip protocol : "+str(protocalIdentifier)
    ipHeaderLen = (ord(payload[0])&0xf)*4
    #print "ip header len : "+str(ipHeaderLen)
    tcp = payload[ipHeaderLen:]
    tcpHeaderLen = (ord(tcp[12]) >> 4) * 4
    tcpData = tcp[tcpHeaderLen:]
    #print "tcpHeaderLen : "+str(tcpHeaderLen)

    host = getHost(tcpData)
    if not host:    #not HTTP or something wrong
	#print "CANT FIND HOST"
        return 1
    searchResult = check(u64(sha256(host).digest()[:8]))
    #check if domain is in block table!
    if searchResult == -1:
        return 1
    else:
	print "Blocking %s..."%(host)
        return 0

def callBack(pkt):
    payload=pkt.get_payload()
    isValid = hostCheck(payload)
    if isValid:
        pkt.accept()
    else:
        pkt.drop()
    return

def main_init():
    cmd = "sudo iptables -A OUTPUT -p tcp -j NFQUEUE\n"
    cmd += "sudo iptables -A INPUT -p tcp -j NFQUEUE\n"
    os.system(cmd)

def fini():
    cmd = "sudo iptables -F\n"
    os.system(cmd)
	
if __name__=="__main__":
    main_init()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, callBack)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
	fini()
	nfqueue.unbind()
        print(' ')

    
    
