from scapy.all import *
import json
import re
from analyser.utils import determine_model
from analyser.utils import analyse_airplay_record
from analyser.utils import analyse_raop_record
from analyser.utils import analyse_mi_connect_record
from analyser.utils import analyse_device_info_record
from analyser.utils import remove_service_from_name
from tabulate import tabulate
from time import sleep
from analyser.config import args
from statistics import fmean

class Device:
    def __init__(self, p: scapy.packet.Packet):
        self.producer = "unknown"
        self.hostname = "unknown"
        self.model = "unknown"
        self.operating_system = "unknown"

        self.mac_address = ""
        self.ip_address = ""

        self.packets = 1
        self.services = dict()

        self.device_info = dict()

        if IP in p:
            self.ip_address = p[IP].src

        d = p[DNS]
        self.mac_address = p[Ether].src

        if DNSRR in d:
            self.analyse_dnsrr(d)
        
        if DNSQR in d:
            self.analyse_dnsqr(d)



    def update(self, p: scapy.packet.Packet):
        self.packets = self.packets + 1
        if self.ip_address == "":
            if IP in p:
                self.ip_address = p[IP].src

            if IPv6 in p:
                self.ip_address = p[IPv6].src

        if DNS not in p:
            return
        d = p[DNS]

        if DNSRR in d:
            self.analyse_dnsrr(d)

        if DNSQR in d:
            self.analyse_dnsqr(d)

    def analyse_dnsqr(device, d: scapy.layers.dns.DNSQR):
        count = d.qdcount

        for i in range(count):
            q = d.qd[i]

            if q.qtype == 12:
                if q.qname.decode('utf8') not in device.services:
                    device.services[q.qname.decode('utf8')] = 1
                else:
                    device.services[q.qname.decode('utf8')] += 1

            if q.qtype not in [1,255]:
                continue

            if device.hostname == "unknown":
                if b'arpa' in q.qname:
                    return 

                if b'mobdev2' in q.qname: 
                    return 

                if b'mi-connect' in q.qname:
                    return
                device.hostname = remove_service_from_name(q.qname.decode('utf8'))

        
    def analyse_dnsrr(self, d: scapy.layers.dns.DNSRR):
        count = d.ancount

        for i in range(count):
            res = d.an[i]

            if res.type == 16:
                rdata = res.rdata 
                for data in rdata:
                    data = str(data, encoding='utf-8')
                    if '=' not in data:
                        continue
                    data = data.split("=")
                    key, value = data[0], data[1]
                    self.device_info[key] = value

            if b'airplay' in res.rrname:
                analyse_airplay_record(self, res)
                continue 

            if b'raop' in res.rrname:
                analyse_raop_record(self, res)
                continue

            if b'._mi-connect' in res.rrname:
                analyse_mi_connect_record(self, res)
                continue

            if b'device-info' in res.rrname:
                analyse_device_info_record(self, res)
                continue

            if b'companion-link' in res.rrname:
                if self.producer == "unknown":
                    self.producer = "Apple"


    def json(self):
        res = '{' + '"producer":"{}","hostname":"{}","mac_address":"{}","ip_address":"{}","packets":{}'.format(self.producer, self.hostname,self.mac_address,self.ip_address,self.packets)


        if self.model != "unknown":
            res += ',"model":"{}"'.format(self.model)
        if self.operating_system != "unknown":
            res += ',"operating_system":"{}"'.format(self.operating_system)
            
        if len(self.services) > 0:
            res += ',"services":'
            services = []
            for name, count in self.services.items():
                services.append('{' + '"name":"{}", "count":{}'.format(name, count) + '}') 

            res += "[" + (",".join(services)) + "]"
        res += '}'
        return res


    def get_similarity_index(self,device):
        similarity = []

        if device.hostname == self.hostname: 
            similarity.append(1)
        
        # jaccard-coefficient
        sset = set(self.services.keys())
        dset = set(device.services.keys())
        if len(sset.union(dset)) == 0:
            similarity.append(0)
        else:
            similarity.append((len(sset.intersection(dset)) / len(sset.union(dset))))


        sset = set(self.device_info.keys())
        dset = set(device.device_info.keys())
        if len(sset.union(dset)) == 0:
            similarity.append(0)
        else:
            similarity.append((len(sset.intersection(dset)) / len(sset.union(dset))))

        device_info_similarity = 0
        cnt = 0
        for k,v in self.device_info.items():
            if k in device.device_info:
                cnt += 1
                if device.device_info[k] == self.device_info[k]:
                    device_info_similarity += 1 

        if cnt != 0:
            similarity.append(device_info_similarity/cnt)
        
        return fmean(similarity) 


    def __str__(self):

        s = "Hostname: \t\t{}\n".format(self.hostname)

        if self.producer != "unknown":
            s += "Producer: \t\t{}\n".format(self.producer)

        if self.model != "unknown":
            s += "Model: \t\t\t{}\n".format(self.model)

        if self.operating_system != "unknown":
            s += "OS: \t\t\t{}\n".format(self.operating_system)


        s += "IP Address: \t\t{}\nMAC Address: \t\t{}\nPacket count: \t\t{}\n".format(self.ip_address, self.mac_address, str(self.packets))

        if len(self.services) > 0:
            ser_head = ["service", "count"]
            ser_rows = []
            for ser, cnt in self.services.items():
                ser_rows.append([ser,cnt])
            
            s += "Services:\n{}".format(tabulate(ser_rows, headers=ser_head))


        return s + "\n"


    def __repr__(self):
        return self.__str__()
