from scapy.all import *
import json
import re

class Device:
    def __init__(self, p):
        self.probable_hostname = "unknown"
        self.probable_producer = "unknown"
        self.probable_model = "unknown"

        self.mac_address = ""
        self.ip_address = ""

        self.packets = 1
        self.services = dict()
        self.device_info = dict()

        d = p[DNS]
        if DNSQR not in d:
            return
        qr = d[DNSQR]
        if qr.qtype != 255:
            return
        
        service_name = qr.qname.decode('utf8')
        if "ip6.arpa" in service_name or "local" not in service_name:
            return
        self.mac_address = p[Ether].src
        self.ip_address = p[IP].src
        self.probable_producer = self.determine_probable_producer(service_name)


    def update(self, p):
        self.packets = self.packets + 1

        d = p[DNS]
        if self.probable_hostname == "unknown":
            self.probable_hostname = self.determine_probable_hostname(d)

        if DNSRR in d:
            self.get_device_info(p)

        self.get_services(p)
        


    def get_device_info(self, p):
        d = p[DNS][DNSRR]
        info = d.rdata
        device_id = 'deviceid={}'.format(self.mac_address.upper())

        if type(info) != list:
            return

        if bytearray(device_id, encoding='utf8') in info:
            for i in info:
                si = i.decode('utf8')
                kv = si.split('=')
                self.device_info[kv[0]] = re.sub(",",".", kv[1])
                if kv[0] == "model":
                    self.probable_model = re.sub(",",".", kv[1])

    def get_services(self, p):
        d = p[DNS]
        cnt = d.qdcount
        for i in range(cnt):
            if hasattr(d.qd[i], "qname"):
                if d.qd[i].qtype != 12:
                    continue
                name = d.qd[i].qname.decode('utf8')
                
                if self.probable_producer == "unknown":
                    low = name.lower()
                    if any(map(low.__contains__, ['airplay', 'sleep-proxy', 'companion-link', 'macbook', 'ipod'])):
                        self.probable_producer= "Apple"

                if name not in self.services:
                    self.services[name] = 1
                else:
                    self.services[name] = self.services[name]+1

    
    def determine_probable_hostname(self, d):
        name = ""
        if d.ancount != 0:
            if DNSRR in d:
                name = str(d[DNSRR].rrname, encoding='utf8')
            else:
                return "unknown"

        if DNSQR in d:
            name = str(d[DNSQR].qname, encoding='utf8')

        if name[0] == "_" or ".ip6.arpa." in name:
            return "unknown"

        pattern = "(\._[a-zA-Z\-]+\._(tcp|udp))?\.local\."
        head = re.sub(pattern, "", name)
        if '._mi-connect' in name:
            prop = json.loads(head)
            return prop['nm']

        if '._tcp' in head:
            return "unknown"

        return head

    def determine_probable_producer(self, name):
        if '._mi-connect' in name:
            return "Xiaomi"

        low = name.lower()
        if any(map(low.__contains__, ['iphone', 'i pad', 'ipad', 'macbook', 'ipod'])):
            return "Apple"

        if 'android' in low:
            return "Android"

        return "unknown"

    def __str__(self):
        ser = ""
        for s in self.services.items():
            ser += str(s)

        return "Probable hostname: {}\nProbable producer: {}\nIP Address: {}\nMAC Address: {}\nPacket count: {}\nServices: {}\n".format(self.probable_hostname, self.probable_producer, self.ip_address, self.mac_address, str(self.packets), ser)

    def __repr__(self):
        return self.__str__()
