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

### Sample output

#### Many packages as a table
Command: `python3 main.py -c 0 -t file -r <some_capture>.pcap`
Output:

```
name                                  producer    model           ip_address     mac_address          packet_count    n_services
------------------------------------  ----------  --------------  -------------  -----------------  --------------  ------------
mallory-iphone                        Apple       unknown         1.2.3.4        01:02:03:04:05:06             909             5
iPad von Bob                          Apple       unknown         1.2.3.5        01:02:03:04:05:06             452             4
Alice's iPhone (2)                    Apple       unknown         1.2.3.6        01:02:03:04:05:06             204             6
Carol MacBook Air                     Apple       MacBookAir9.1   1.2.3.7        01:02:03:04:05:07             241            18
```

#### Packages from one device 
Command: `python3 main.py -m '01:02:03:04:05:06' file -r <some_capture>.pcap`
Output:
```
Probable hostname:      mallory-iphone
Probable producer:      Apple
IP Address:             1.2.3.4
MAC Address:            01:02:03:04:05:06
Packet count:           97
Services: 
service                        count
---------------------------  -------
_service1._tcp.local.             21
_cool-service._tcp.local.         21
_fun._udp.local.                  21
_here-i-am._tcp.local.             5

```
