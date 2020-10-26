Viewing packets like in Wireshark
---------------------------------

.. index::
   single: viewer()

Problem
^^^^^^^
You want to see packets as in Wireshark with great flexibility.

Solution
^^^^^^^^
That's what :py:func:`viewer` is for!

.. image:: graphics/animations/animation-scapy-packet-viewer.svg


.. py:function:: viewer(source, ...)

    It allows you to inspect, edit and filter lists of packets or shows
    all captured packets on an interface. All packets can be modified in the terminal
    interface. Any packet can be re-send on the current interface and new packets
    can be crafted.

Columns
^^^^^^^

There are three groups of columns.
The viewer will always show the default columns.
If the user provides a custom configuration these columns will be shown.
If the user provides a ``basecls``, the packet viewer will try to get a
``basecls`` specific configuration from ``conf.contribs["packet_viewer_columns"]``. If no configuration
is present, the packet viewer will automatically create columns from the
``field_desc`` of the ``basecls``.

+---------------------+----------------------------+---------------------------------------------+
| Default             | Additional columns         | basecls                                     |
+=====================+============================+=============================================+
| NO, TIME            | Defined by the user        | The fields of the basecls.                  |
|                     | with                       | Example: UDP --> SPORT, DPORT, LEN, CHKSUM  |
|                     | ``viewer(s, cols, ...)``   |                                             |
|                     | or defined in the config   |                                             |
+---------------------+----------------------------+---------------------------------------------+


`Example: Default columns`

``viewer(s)``
will have this columns:

``NO, TIME, REPR``

The viewer will add the ``REPR`` column if no basecls is specified.
This allows the user to see the most important data.


`Example: Custom configuration`

``viewer(s, [("MyLengthColumn", 10, len)], UDP)``
will have these columns:

``NO, TIME, MyLengthColumn, PAYLOAD``


`Example: Auto-generated columns from basecls`

``viewer(s, UDP)``
will have these columns:

``NO, TIME, SPORT, DPORT, LEN, CHKSUM, PAYLOAD``


`Example: Columns from configuration for basecls`

``conf.contribs["packet_viewer_columns"]["UDP"] = [("MyLengthColumn", 10, len)]``
``viewer(s, UDP)``
will have these columns:

``NO, TIME, MyLengthColumn, PAYLOAD``

Example script
^^^^^^^^^^^^^^

The following script displays all Ethernet packets received by the specified `L2Socket`.
All selected packets will be sent on the same socket after quitting the viewer.
Note that this script might require root privileges.


.. code:: python

    from scapy.arch import L2Socket
    from scapy.layers.l2 import Ether
    from scapy.modules.packet_viewer.viewer import viewer

    socket = L2Socket("eth0")
    selected, _all = viewer(socket, basecls=Ether, globals_dict=globals())
    [socket.send(p) for p in selected]

    socket.close()

Views
^^^^^

:py:func:`viewer` takes a `views` argument. Views can offer additional information and features.

The views are independent from the Packet Viewer. They communicate only over interfaces.
So a plugin structure is used.

In `DetailsView` is the interface defined. It also offers the necessary structure to create a new view.
`EditView` is an example of an already implemented view.

The `views` argument takes the views which should be accessible in the viewer.
If none specified, it only adds the `EditView`.
