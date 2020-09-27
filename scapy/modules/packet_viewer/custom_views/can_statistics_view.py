from urwid import ListBox, SimpleListWalker, Pile, Padding

from scapy.modules.packet_viewer.custom_views.message_information import \
    MessageDetailsData
from scapy.modules.packet_viewer.show_view import DetailsView


class CanDetailsView(DetailsView):
    action_name = "Statistics"

    palette = [
        ("bold-yellow", "yellow,bold", ""),
        ("bold-orange", "bold", ""),
        ("bold-red", "dark red,bold", ""),
        ("bg 1", "", "dark blue"),
        ("bg 2", "", "dark cyan"),
        ("bg 1 line", "", "dark blue"),
        ("bg 2 line", "", "dark cyan")
    ]

    def __init__(self):
        self.pile = Pile([ListBox(SimpleListWalker([]))])
        super(CanDetailsView, self).__init__(self.pile)

    def update_packets(self, focused_packet, all_packets):
        packets = [bytearray(packet.data) for packet in all_packets
                   if focused_packet.identifier == packet.identifier and
                   len(focused_packet.data) == len(packet.data)]
        message_details = MessageDetailsData(packets)
        message_details.set_detailed_message_information()
        message_details.create_graph()
        message_details.create_bit_correlation()

        body = SimpleListWalker(
            [
                message_details.byte_heat_map,
                message_details.bit_heat_map,
                message_details.corr_coeff,
            ]
        )
        statistic_analysis = Padding(ListBox(body), left=1, right=1)
        widget_list = [(statistic_analysis, ("weight", 0.3)),
                       (message_details.graph, ("weight", 0.7))]
        del self.pile.contents[:]
        self.pile.contents.append(widget_list[0])
        self.pile.contents.append(widget_list[1])
