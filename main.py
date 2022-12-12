from scapy.all import *
import device


summary = dict()

def hereweare(p):


    if p[Ether].src not in summary:
        de = device.Device(p)
        if de.mac_address == "":
            return
        summary[p[Ether].src] = de
    else:
        summary[p[Ether].src].update(p)




sniffed = sniff(offline='all.pcap', filter='udp port 5353', prn=hereweare)
print(sniffed)

print(summary)
