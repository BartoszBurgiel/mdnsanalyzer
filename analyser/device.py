from scapy.all import *
import json
from requests import get
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

class Device:
    def __init__(self, p):
        self.producer = "unknown"
        self.hostname = "unknown"
        self.model = "unknown"

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



    def update(self, p):
        self.packets = self.packets + 1
        if self.ip_address == "":
            if IP in p:
                self.ip_address = p[IP].src

        if DNS not in p:
            return
        d = p[DNS]

        if DNSRR in d:
            self.analyse_dnsrr(d)

        if DNSQR in d:
            self.analyse_dnsqr(d)

    def analyse_dnsqr(device, d):
        count = d.qdcount

        for i in range(count):

            q = d.qd[i]
            if q.qtype not in [1,255]:
                return

            if device.hostname == "unknown":
                if b'arpa' in q.qname:
                    return 

                if b'mobdev2' in q.qname: 
                    return 

                if b'mi-connect' in q.qname:
                    return
                device.hostname = remove_service_from_name(q.qname.decode('utf8'))

        
    def analyse_dnsrr(self, d):
        count = d.ancount

        for i in range(count):
            res = d.an[i]

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

            if b'companion-link' in res.rrname:
                if self.producer == "unknown":
                    self.producer = "Apple"

    def __str__(self):
        ser_head = ["service", "count"]
        ser_rows = []
        for s,c in self.services.items():
            ser_rows.append([s,c])
    
        info_head = ["spec", "value"]
        info_rows = []
        for s, v in self.device_info.items():
            info_rows.append([s, v])

        return "\nHostname: \t\t{}\nProducer: \t\t{}\nModel: \t\t\t{}\nIP Address: \t\t{}\nMAC Address: \t\t{}\nPacket count: \t\t{}\nServices: \n{}\n\nDevice info: \n{}\n".format(self.hostname, self.producer, self.model, self.ip_address, self.mac_address, str(self.packets), tabulate(ser_rows, headers=ser_head), tabulate(info_rows, headers=info_head))

    def __repr__(self):
        return self.__str__()
