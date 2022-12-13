from scapy.all import *
import result

res = result.Result()


sniffed = sniff(offline='all.pcap', filter='udp port 5353', prn=res.update)

print(res)

