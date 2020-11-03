[![PyPI](https://img.shields.io/pypi/v/scapy-packet_viewer.svg)](https://pypi.org/project/scapy-packet_viewer/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/scapy-packet_viewer.svg)](https://pypi.org/project/scapy-packet_viewer/)
[![Documentation Status](https://readthedocs.org/projects/scapy-packet_viewer/badge/?version=latest)](https://scapy-packet_viewer.readthedocs.io/en/latest/?badge=latest)

TODO: non-Travis build status

# scapy-packet_viewer #

Packet viewer for SecDev's [Scapy](https://scapy.net/).

## Installation ##

Install the latest release using pip (`pip install scapy-packet_viewer`) or manually from source by running `pip install .` (preferred) or `python setup.py install` in the cloned repository.

`scapy-packet_viewer` by itself only installs the minimum required dependencies to run the bare packet viewer, but not any of its custom views. To install dependencies for those too, use `scapy-packet_viewer[full]` instead (or run `pip install .[full]` in the project root).
