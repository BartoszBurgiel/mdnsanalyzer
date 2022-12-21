from scapy.all import *
import json
from requests import get
import re
from analyser.utils import determine_model
from tabulate import tabulate
from time import sleep
from analyser.config import args

class Device:
    def __init__(self, p):
        self.producer = "unknown"
        self.model = "unknown"

        self.mac_address = ""
        self.is_mac_random = True
        self.ip_address = ""

        self.packets = 1
        self.services = dict()
        self.device_info = dict()

        d = p[DNS]
        self.mac_address = p[Ether].src
        self.hostname = self.determine_hostname(d)

        if IP in p:
            self.ip_address = p[IP].src

        if DNSQR not in d:
            return

        qr = d[DNSQR]
        if qr.qtype not in [255]:
            return
        
        service_name = qr.qname.decode('utf8')
        if "arpa" in service_name or "local" not in service_name:
            self.hostname = "unknown" 

        threading.Thread(target=self.determine_producer, args=[self.mac_address, service_name]).start()



    def update(self, p):
        self.packets = self.packets + 1
        if self.ip_address != "":
            if IP in p:
                self.ip_address = p[IP].src

        if DNS not in p:
            return
        d = p[DNS]
        if self.hostname == "unknown":
            self.hostname = self.determine_hostname(d)

        if DNSRR in d:
            self.get_device_info(p)

        self.get_services(p)
        
    def get_device_info(self, p):
        d = p[DNS][DNSRR]
        count = p[DNS].ancount
        for i in range(count):
            ans = p[DNS].an[i]
            if "device-info" in ans.rrname.decode('utf8'):
                info = ans.rdata
                for inf in info:
                    if type(inf) == int:
                        continue
                    si = inf.decode('utf8')
                    if "=" not in si:
                        continue

                    kv = si.split('=')

                    self.device_info[kv[0]] = re.sub(",",".", kv[1])
                    if kv[0] == "model":
                        if self.model == "unknown":
                            self.model = determine_model(re.sub(",", ".", kv[1]))

    def get_services(self, p):
        d = p[DNS]
        cnt = d.qdcount
        for i in range(cnt):
            if hasattr(d.qd[i], "qname"):
                if d.qd[i].qtype != 12:
                    continue
                name = d.qd[i].qname.decode('utf8')
                
                if self.producer == "unknown":
                    low = name.lower()
                    if any(map(low.__contains__, ['airplay', 'sleep-proxy', 'companion-link', 'macbook', 'ipod', 'rdlink'])):
                        self.producer= "Apple"

                if name not in self.services:
                    self.services[name] = 1
                else:
                    self.services[name] = self.services[name]+1

    
    def determine_hostname(self, d):
        pattern = "(\._[a-zA-Z\-]+\._(tcp|udp))?\.local\."
        name = "unknown"
        
        if DNSRR in d:
            count = d.ancount
            for q in range(count):
                rr = d.an[q]
                name = rr.rrname.decode('utf8')
                if rr.type == 16 and "device-info" in name:
                    name = re.sub(pattern, "", name)
                    return name

                if rr.type == 12:
                    name = rr.rdata.decode('utf8')
                    if "arpa" in name:
                        name = re.sub(pattern, "", name)
                        return name

                    if "._mi-connect" in name:
                        name = re.sub(pattern, "", name)
                        prop = json.loads(name)
                        return prop['nm']

                if rr.type == 1:
                    name = rr.rrname.decode('utf8')
                    name = re.sub(pattern, "", name)
                    return name

        name = "unknown"
        if DNSQR in d:
            count = d.qdcount 
            for q in range(count):
                q = d.qd[q]
            if d[DNSQR].qtype != 16:
                return "unknown"
            name = str(d[DNSQR].qname, encoding='utf8')

        if name[0] == "_" or ".arpa." in name:
            return "unknown"
        return "unknown"

    def determine_producer(self, mac, name):
        self.determine_producer_from_name(name)
        if self.producer != "unknown":
            return
        self.determine_producer_from_mac(mac)

    def determine_producer_from_name(self, name):
        if '._mi-connect' in name:
            self.producer = "Xiaomi"
            return

        low = name.lower()
        if any(map(low.__contains__, ['iphone', 'i pad', 'ipad', 'macbook', 'ipod'])):
            self.producer =  "Apple"
            return

        if 'android' in low:
            self.producer =  "Android"
            return


    def determine_producer_from_mac(self, mac):
        if not args.offline:
            return

        url = 'https://api.maclookup.app/v2/macs/' + mac
        try:
            res = get(url).text
        except:
            return
        j = json.loads(res)
        
        if not j['success']:
            if j['errorCode']== 429:
                sleep(0.5)
                return self.determine_producer_from_mac(mac)
            return 

        if j['success']:
            if j['found']:
                self.producer =  j['company']
                self.is_mac_random = j['isRand']
        
            return 



    def __str__(self):
        ser_head = ["service", "count"]
        ser_rows = []
        for s,c in self.services.items():
            ser_rows.append([s,c])
    
        info_head = ["spec", "value"]
        info_rows = []
        for s, v in self.device_info.items():
            info_rows.append([s, v])

        return "\nHostname: \t\t{}\nProducer: \t\t{}\nModel: \t\t\t{}\nIP Address: \t\t{}\nMAC Address: \t\t{}\nIs MAC random?: \t{}\nPacket count: \t\t{}\nServices: \n{}\n\nDevice info: \n{}\n".format(self.hostname, self.producer, self.model, self.ip_address, self.mac_address, self.is_mac_random, str(self.packets), tabulate(ser_rows, headers=ser_head), tabulate(info_rows, headers=info_head))

    def __repr__(self):
        return self.__str__()
