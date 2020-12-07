from scapy.contrib.cansocket_native import CANSocket
from scapy.layers.can import CAN
from scapy_packet_viewer import viewer

socket = CANSocket("vcan0")
viewer(socket, None, basecls=CAN, globals_dict=globals())
