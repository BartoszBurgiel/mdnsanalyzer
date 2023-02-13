from analyser.device import Device
from os import system
from scapy.all import *
from scapy.layers.l2 import Ether
from tabulate import tabulate
from datetime import datetime

class Result:

    def __init__(self):
        self.packets = 0
        self.start = datetime.now()
        self.devices = dict() 

    def update(self, p: scapy.packet.Packet):
        self.packets = self.packets + 1
        mac = p[Ether].src
        if mac not in self.devices:
            de = Device(p)
            if de.mac_address == "":
                return
            self.devices[mac] = de
        else:
            self.devices[mac].update(p)

    def csv(self):
        print("name,producer,model,operating_system,ip_address,mac_address,packet_count,services")
        for s in self.devices.values():
            print('"{}",{},"{}","{}",{},{},{},"{}"'.format(s.hostname, s.producer, s.model,s.operating_system, s.ip_address, s.mac_address,s.packets,";".join(s.services.keys())))

    def json(self):
        res = '{"devices":['
        dev = []
        for s in self.devices.values():
            dev.append(s.json())
        res += ",".join(dev)
        return res + "]}"

    def table(self):
        headers = ["name","producer","model", "ip_address","mac_address","packet_count","n_services"]
        data = []
        for s in self.devices.values():
            data.append([s.hostname, s.producer, s.model, s.ip_address, s.mac_address,s.packets,len(s.services)])

        print(tabulate(data, headers=headers))

    def print_report(self):
        print("Total examined packages: {}\nDuration: {}s\n".format(self.packets, (datetime.now()-self.start).seconds))


    def get_similarity_tree(self):
        sim = self.devices.values()
        similarity = dict()
        for d in sim:
            if d.producer == "unknown" or d.hostname == "unknown" or len(d.services) < 1:
                continue

            similarity[d.hostname] = dict()
            for r in sim:
                s = d.get_similarity_index(r)
                if s < 0.5:
                    continue
                if d.hostname == r.hostname:
                    similarity[d.hostname][r.mac_address] = s 
                    continue
                
                similarity[d.hostname]['other'] = dict()
                similarity[d.hostname]['other'][r.mac_address] = s

        return  {k:v for k, v in similarity.items() if len(v) > 2}

    def __str__(self):
        out = ""
        for v in self.devices.values():
            out += str(v)
            out += "\n"

        return out

    def __repr__(self):
        return self.__str__()
