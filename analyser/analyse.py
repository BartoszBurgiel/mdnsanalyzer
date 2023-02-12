from analyser.config import args
from scapy.all import *
from analyser.result import Result
from analyser.utils import Recorder
from analyser.utils import printer

def analysePackets():
    res = Result()

    default_filter = "udp port 5353"

    if args.mac != None:
        default_filter += " and ether src host {}".format(args.mac)

    if args.filter != None:
        default_filter += " and {}".format(args.filter)
    
    if args.input == "live":
        Thread(target=printer, args=[res, args]).start()
        if args.save_to_file != None:
            recorder = Recorder(args.save_to_file, res)
            sniff(count=args.count, filter=default_filter, iface=args.interface[0], prn=recorder.analyze_and_record)
        else:
            sniff(count=args.count, filter=default_filter, iface=args.interface[0], prn=res.update)
    else:
        for f in args.read_file:
            if args.table or not (args.csv or args.json):
                print("Analyzing ", f, "...")

            sniff(offline=f, filter=default_filter, count=args.count, prn=res.update, quiet=True)

    if args.csv:
        res.csv()
    elif args.table:
        res.table()
    elif args.json:
        print(res.json())
    else:
        print(res)


    if args.similarity:

        sim = res
        sim = sim.devices.values()
        sim = filter(lambda x : x.hostname != "unknown" and len(x.services) != 0, sim)
        sim = list(sim)

        dev_count = len(sim)
        adjacency_matrix = [[None] + [x.hostname for x in sim]]

        for d in sim:
            adjacency_matrix.append([d.hostname] + [d.get_similarity_index(x) for x in sim]) 

        import csv
        with open(args.similarity[0], "w") as f:
            writer = csv.writer(f)
            writer.writerows(adjacency_matrix)
    if args.table or not (args.csv or args.json):
        res.print_report()
