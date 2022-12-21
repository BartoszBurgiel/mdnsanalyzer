from sys import argv, exit
import argparse
from scapy.interfaces import get_if_list

parser = argparse.ArgumentParser(
        prog="mdns-analyzer",
        description = "Get an overview of the information about devices in the network from the MDNS traffic.",
        epilog="With great power comes great responsibility")

parser.add_argument('-c', '--count', nargs="?", metavar=100, default=0, type=int, help="Analyze only this many packets. Applies both to the file and the live capturing. 0 means infinite amount of packets")
parser.add_argument('-f', '--filter', nargs="?", help="BFP filter that will be appended to the default MDNS filter: udp port 5353 and ([filter]).")
parser.add_argument('-m', '--mac', nargs="?", type=str, help="Analyse packets which originate from this mac address.")
parser.add_argument('-o', '--offline', nargs="?", type=bool, default=True, help="Do not run any internet queries for better results, like mac address lookups. ")

output_group = parser.add_mutually_exclusive_group()
output_group.add_argument('-csv', help="Print the results in a CSV format", action='store_true')
output_group.add_argument('-t', '--table', help="Print the results in a pretty table", action='store_true')

input_subparsers = parser.add_subparsers(help="Choose between analyzing a file or live capturing ", dest="input")

live_config = input_subparsers.add_parser("live", help="Set the interface on which the analyzer should listen to the packages (requires sudo permissons)")
live_config.add_argument('-i', '--interface',nargs=1, choices=get_if_list(), metavar=get_if_list(), help="select an interface to listen to", required=True, type=str)
live_config.add_argument('-s', '--save-to-file', help="Save the packets to a file when using the live listening mode.", type=str)

file_config = input_subparsers.add_parser("file", help="provide file(s) to analyze")
file_config.add_argument('-r', '--read-file', nargs="+", metavar="capture.pcap", help="mdns-analyzer will read the provided file(s)", required=True)


args = None
if len(argv) < 2:
    parser.print_help()
    exit(1)

try:
    args = parser.parse_args()
except:
    parser.print_help()
    exit(1)

