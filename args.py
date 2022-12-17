import argparse
from scapy.interfaces import get_if_list
from scapy.sendrecv import sniff
import result

parser = argparse.ArgumentParser(
        prog="mdns-analyzer",
        description = "Get an overview of the information about devices in the network from the MDNS traffic.",
        epilog="With great power comes great responsibility")

parser.add_argument('-c', '--count', nargs="?", metavar=100, default=100, type=int, help="Analyze only this many packets. Applies both to the file and the live capturing. 0 means infinite amount of packets")
parser.add_argument('-f', '--filter', nargs="?", help="BFP filter that will be appended to the default MDNS filter: udp port 5353 and ([filter]).")

input_subparsers = parser.add_subparsers(help="Choose between analyzing a file or live capturing ", dest="input")

live_config = input_subparsers.add_parser("live", help="Set the interface on which the analyzer should listen to the packages (requires sudo permissons)")
live_config.add_argument('-i', '--interface',nargs=1, choices=get_if_list(), metavar=get_if_list(), help="select an interface to listen to", required=True, type=str)

file_config = input_subparsers.add_parser("file", help="provide file(s) to analyze")
file_config.add_argument('-r', '--read-file', nargs="+", metavar="capture.pcap", help="mdns-analyzer will read the provided file(s)", required=True)


args = parser.parse_args()
result = result.Result()

def analyze():
    
    default_filter = "udp port 5353"

    if args.filter != None:
        default_filter += " and {}".format(args.filter)
    
    if args.input == "live":
        sniff(count=args.count, filter=default_filter, iface=args.interface[0], prn=result.update)
    else:
        for f in args.read_file:
            sniff(offline=f, filter=default_filter, count=args.count, prn=result.update, quiet=True)
