# MDNS analyzer

This script provides a neat overview over the received MDNS traffic. 

## Installation

After installing the dependencies with `pip install -r requirements.txt`, the script is ready to use.

## Usage

To run the script just type `./main.py` into the terminal. 


```
usage: mdns-analyzer [-h] [-c [100]] [-f [FILTER]] [-m [MAC]] [-csv | -t] {live,file} ...

Get an overview of the information about devices in the network from the MDNS traffic.

positional arguments:
  {live,file}           Choose between analyzing a file or live capturing
    live                Set the interface on which the analyzer should listen to the packages (requires sudo permissons)
    file                provide file(s) to analyze

optional arguments:
  -h, --help            show this help message and exit
  -c [100], --count [100]
                        Analyze only this many packets. Applies both to the file and the live capturing. 0 means infinite amount of packets
  -f [FILTER], --filter [FILTER]
                        BFP filter that will be appended to the default MDNS filter: udp port 5353 and ([filter]).
  -m [MAC], --mac [MAC]
                        Analyse packets which originate from this mac address.
  -csv                  Print the results in a CSV format
  -t, --table           Print the results in a pretty table

With great power comes great responsibility

```
