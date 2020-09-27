# coding=utf-8

from typing import Tuple, List, Union, Optional
from urwid import Text, LineBox

from scapy.modules.packet_viewer.custom_views.funcs import (
    byte_flips,
    bit_flips,
    graph_values,
    bit_flip_correlation,
)
from scapy.modules.packet_viewer.custom_views.utils import create_flips_heat_map
from scapy.modules.packet_viewer.custom_views.graph_view import GraphView


class MessageDetailsData:
    def __init__(
        self, data_strings  # type: List[bytes]
    ):
        self.all_data = data_strings
        self.byte_heat_map = []  # type: List[Union[Tuple[str, str], str]]
        self.bit_heat_map = []  # type: List[Union[Tuple[str, str], str]]
        self.graph = None  # type: Optional[LineBox]
        self.corr_coeff = None  # type: Optional[Text]

    def set_detailed_message_information(self):
        byte_changes = byte_flips(self.all_data)  # type: Optional[List[int]]
        bit_changes = bit_flips(self.all_data)  # type: Optional[List[int]]

        self.byte_heat_map = create_flips_heat_map(byte_changes, "Byteflips: ")
        self.bit_heat_map = create_flips_heat_map(bit_changes, "Bitflips: ")

    def create_graph(self):
        graph_data, graph_maximum = graph_values(self.all_data)
        self.graph = LineBox(GraphView(graph_data, graph_maximum),
                             "Data over time",
                             lline="", rline="", bline="",
                             blcorner="", brcorner="",
                             trcorner=u"─", tlcorner=u"─")

    def create_bit_correlation(self):
        correlations = bit_flip_correlation(self.all_data)  # type: Optional[List[float]]
        formatted_corr = [
            ("default_bold", "Bitflip Correlation of consecutive bits: ")
        ]  # type: List[Union[Tuple[str, str], str]]
        for corr in correlations:
            if corr is None:
                formatted_corr.append("- | ")
                continue
            if corr == 0:
                layout = "default"
            elif 0 < corr < 0.5:
                layout = "bold-yellow"
            elif corr <= 0.5:
                layout = "green"
            elif 0 > corr >= -0.5:
                layout = "bold-orange"
            else:
                layout = "bold-red"
            formatted_corr.append((layout, str(round(corr, 2))))
            formatted_corr.append(" | ")
        self.corr_coeff = Text(formatted_corr)
