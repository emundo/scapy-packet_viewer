# SPDX-License-Identifier: GPL-2.0-only

from typing import List, Tuple, Callable

from scapy.config import conf
from scapy.packet import Packet

if "packet_viewer_columns" not in conf.contribs:
    conf.contribs["packet_viewer_columns"] = dict()

payload_column = [("PAYLOAD", 50, lambda p: repr(p.payload))]
repr_column = [("REPR", 50, repr)]  # type: List[Tuple[str, int, Callable[[Packet], str]]]  # noqa: E501

# ############### ISOTP ###################

conf.contribs["packet_viewer_columns"]["ISOTP"] = [
    ("SRC", 6, lambda p: format(p.src, "03X")),
    ("DST", 6, lambda p: format(p.dst, "03X")),
    ("DATA", 100, lambda p: repr(p.data))]
