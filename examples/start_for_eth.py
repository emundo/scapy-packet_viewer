# To enable all packet dissections known by scapy
# noinspection PyUnresolvedReferences
from scapy.all import *
from scapy.arch import L2Socket
from scapy.layers.l2 import Ether
from scapy_packet_viewer import viewer

socket = L2Socket()
viewer(socket, None, basecls=Ether, globals_dict=globals())
