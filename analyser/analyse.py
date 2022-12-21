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
            print("Analyzing ", f, "...")
            sniff(offline=f, filter=default_filter, count=args.count, prn=res.update, quiet=True)

    if args.csv:
        res.csv()
    elif args.table:
        res.table()
    else:
        print(res)

    res.print_report()
