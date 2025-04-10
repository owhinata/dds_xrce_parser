# dds_xrce_parser

Decode micro-ROS messages from a captured pcapng file

## Prepareation

```bash
sudo apt-get install tshark
pip install pyshark
```

## Usage

```bash
usage: dds_xrce_parse.py [-h] [--mode {serial,xrce}] [--decode] input

Extract XRCE packets from pcap.

positional arguments:
  input                 Input pcapng file path

options:
  -h, --help            show this help message and exit
  --mode {serial,xrce}  Dump mode: 'serial' for XRCE-Serial, 'xrce' for XRCE packet only (default)
  --decode              Decode XRCE messages into human-readable format
```
