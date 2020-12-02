Development
=============

UI Overview
-----------

.. image:: graphics/packet_viewer_ui_overview.*

Architecture
---------------------

.. image:: graphics/packet_viewer_architecture_overview.*

* ``init``: Creates object

* ``msg_to_main_thread(<the msg>)``: With this signal other threads can send messages to the main thread, which is thereby awakened and processes this message. The DetailsView is just offering an interface for specialized views. Thus it depends on the implementation, which messages are sent. That's why an Asterik (*) is used there.

* ``add_packet``: Adds a packet to the PacketListView to display.

* ``update_selected_packet``: The MainWindow notifies the PacketListView that the currently selected packet has been modified. Thus the text representing this packet has to be updated.

* ``modified``: That's a predefined signal from urwid. It's emitted by a ListView when the selection changes or when a new item has been added.

* ``update_packets``: The MainWindow notifies a DetailsView that either the selected packet has changed or that a new packet has been received. A DetailsView can react or ignore it.

* ``notification``: Through this signal the DetailsView can display a notification to the user with an info or question popup.

* ``packet_modified``: The DetailsView shall emit this signal if it modified the selected packet. Related to update_selected_packet.
