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


    def get_similarity_tree(self, threshold: float, show_values: bool):
        sim = self.devices.values()
        similarity = dict()
        for d in sim:
            if d.hostname == "unknown" or len(d.services) < 2:
                continue

            similarity[d.hostname] = {'mac_address': d.mac_address, 'similar_devices': []}
            for r in sim:

                if d.hostname == r.hostname and d.mac_address == r.mac_address:
                    continue

                s, v = d.get_similarity_index(r)
                if s < threshold:
                    continue

                o = {
                        'name': r.hostname,
                        'mac_address': r.mac_address,
                        'similarity': s
                        }
                if show_values:
                    o['values'] = v

                similarity[d.hostname]['similar_devices'].append(o) 
                continue
                
        return  {k:v for k, v in similarity.items() if len(v['similar_devices']) > 0}

    def __str__(self):
        out = ""
        for v in self.devices.values():
            out += str(v)
            out += "\n"

        return out

    def __repr__(self):
        return self.__str__()
