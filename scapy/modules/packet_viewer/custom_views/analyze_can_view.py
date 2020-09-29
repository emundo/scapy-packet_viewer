# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Tim Henkes <tim.henkes@e-mundo.de>
# This program is published under a GPLv2 license

import binascii
from collections import namedtuple
from multiprocessing import Process, Queue
import os
from queue import Empty
import struct
from tempfile import TemporaryDirectory
from threading import Thread
from typing import List, Optional, Tuple, Union

import cantools
from cantools.database.can import Database, Message, Signal
import numpy as np
from revdbc import analyze_identifier
import urwid
from urwid.numedit import FloatEdit

from scapy.layers.can import CAN
from scapy.packet import Packet
from scapy.modules.packet_viewer.details_view import DetailsView
from scapy.modules.packet_viewer.custom_views.message_information import \
    MessageDetailsData
from scapy.modules.packet_viewer.custom_views.message_layout_string import \
    message_layout_string

Data = namedtuple("Data", [ "focused_packet", "packets" ])
Success = namedtuple("Success", [ "value" ])
Error = namedtuple("Error", [ "reason" ])


class AnalyzeCANView(DetailsView):
    # TODO: Should probably cache analysis results
    """
    Custom view exclusively for CAN packets which shows the results of the
    structural analysis as performed by the external package "revdbc" and allows
    editing and saving the restored DBC message structures.
    """

    action_name = "Analyze CAN"

    RERUN_ANALYSIS_BUTTON_LABEL = "Rerun Analysis"
    SAVE_BUTTON_LABEL = "Save DBC to:"
    DEFAULT_SAVE_PATH = "~/analyze_can/restored.dbc"

    LETTER_COLUMN_LABEL = "Letter"
    LABEL_COLUMN_LABEL = "Label"
    SIGNED_COLUMN_LABEL = "Signed?"
    FLOAT_COLUMN_LABEL = "Float?"
    OFFSET_COLUMN_LABEL = "Offset"
    SCALE_COLUMN_LABEL = "Scale"
    MINIMUM_COLUMN_LABEL = "Minimum"
    MAXIMUM_COLUMN_LABEL = "Maximum"
    UNIT_COLUMN_LABEL = "Unit"
    DECODED_COLUMN_LABEL = "Decoded Value"

    TABLE_COLUMN_INFO = [
        # (column label, (minimum) width to hold values of this column)
        (LETTER_COLUMN_LABEL, 1),
        (LABEL_COLUMN_LABEL, 30),
        (SIGNED_COLUMN_LABEL, 7),
        (FLOAT_COLUMN_LABEL, 7),
        (OFFSET_COLUMN_LABEL, 5),
        (SCALE_COLUMN_LABEL, 5),
        (MINIMUM_COLUMN_LABEL, 5),
        (MAXIMUM_COLUMN_LABEL, 5),
        (UNIT_COLUMN_LABEL, 4),
        (DECODED_COLUMN_LABEL, 10)
    ] # type: List[Tuple[str, int]]

    TABLE_COLUMN_LABELS = [ label for label, _ in TABLE_COLUMN_INFO ]
    TABLE_COLUMNS = [
        # (column label, column width)
        (label, max(len(label), min_width))
        for label, min_width
        in TABLE_COLUMN_INFO
    ] # type: List[Tuple[str, int]]

    TABLE_COLUMN_DIVIDECHARS = 2
    TABLE_WIDTH = (len(TABLE_COLUMNS) - 1) * TABLE_COLUMN_DIVIDECHARS + sum(
        width for _, width in TABLE_COLUMNS
    )

    def __init__(self):
        # type: () -> None
        cls = self.__class__

        self._current_data = None # type: Optional[Data]
        self._process = None # type: Optional[Process]
        self._last_result = None # type: Optional[Union[Success, Error]]

        self._ascii_art_text = urwid.Text("")
        self._status_text = urwid.Text("No CAN packet selected.")
        self._save_path_edit = urwid.Edit(
            edit_text=cls.DEFAULT_SAVE_PATH,
            wrap='clip'
        )

        self._graph = urwid.WidgetPlaceholder(urwid.SolidFill())

        self._signal_table_walker = urwid.SimpleFocusListWalker([])
        self._signal_table_walker_state = None # type: Optional[message]
        self._signal_table = urwid.ListBox(self._signal_table_walker)

        super(AnalyzeCANView, self).__init__(urwid.Columns([
            ('weight', 1, urwid.Pile([
                ('pack', self._status_text),
                ('pack', urwid.Divider()),
                ('weight', 1, urwid.Filler(urwid.Padding(
                    self._ascii_art_text,
                    align='center',
                    width='pack'
                ))),
                ('pack', urwid.Divider()),
                ('pack', urwid.Pile([
                    ('pack', urwid.Columns([
                        (len(cls.SAVE_BUTTON_LABEL)+4, urwid.Button(
                            cls.SAVE_BUTTON_LABEL,
                            on_press=lambda _: self._save()
                        )),
                        ('weight', 1, self._save_path_edit)
                    ], dividechars=1)),
                    ('pack', urwid.Padding(
                        urwid.Button(
                            cls.RERUN_ANALYSIS_BUTTON_LABEL,
                            on_press=lambda _: self._rerun_analysis()
                        ),
                        align='left',
                        width=len(cls.RERUN_ANALYSIS_BUTTON_LABEL)+4
                    ))
                ]))
            ])),
            (cls.TABLE_WIDTH+1, urwid.Filler(
                urwid.Padding(
                    urwid.Pile([
                        ('weight', 1, urwid.Padding(
                            self._signal_table,
                            align='left',
                            width=cls.TABLE_WIDTH
                        )),
                        ('pack', urwid.Divider()),
                        ('weight', 1, self._graph)
                    ]),
                    align='center',
                    right=1
                ),
                height=('relative', 100),
                top=1,
                bottom=1
            ))
        ], dividechars=1, min_width=40))

    def update_packets(self, focused_packet, all_packets):
        # type: (Packet, List[Packet]) -> None
        if isinstance(focused_packet, CAN):
            packets_to_analyze = list(filter(
                lambda p: (
                    isinstance(p, CAN) and
                    p.identifier == focused_packet.identifier
                ),
                all_packets
            ))

            # Only trigger a new analysis when the identifier changes, not when
            # the packet list changes. Triggering an analysis on a change to the
            # packet list would trigger a new analysis on every incoming packet
            # for that identifier, which might be annoying. Still, changes to
            # the packet list are stored to _current_data, so that a manually
            # restarted analysis has access to the most recent list.
            run_analysis = \
                self._current_data is None or \
                self._current_data.focused_packet.identifier != \
                    focused_packet.identifier

            self._current_data = Data(
                focused_packet=focused_packet,
                packets=packets_to_analyze
            )

            if run_analysis:
                self._start_analysis(self._current_data)
                self._update_views()
        else:
            self._abort_analysis()
            self._current_data = None
            self._update_views()

        self._update_views()

    def _start_analysis(self, data):
        # type: (Data) -> None
        """
        (Re-)start the analysis.
        """
        self._abort_analysis()

        # Yes, the following code is starting both a process and a thread.
        #
        # Threads:
        # - are subject to the GIL (not a big problem here)
        # - can't be terminated without horrible hacks
        #
        # Processes:
        # - can't share (complex) state with the main program and are thus
        #   unable to refresh the UI
        #
        # The main thread:
        # - may obviously not be blocked
        #
        # The only somewhat bareable solution I can think of is doing the
        # following: A process is started to run the analysis, posting the
        # result of the analysis into a queue. A thread is started which
        # blockingly waits for the process to terminate, followed by reading
        # the result from the queue and updating the UI.

        result_queue = Queue()

        self._process = Process(target=self._run_analysis, args=(
            data,
            result_queue
        ))
        self._process.start()

        Thread(
            target=self._wait_for_analysis,
            args=(result_queue,),
            daemon=True
        ).start()

    def _abort_analysis(self):
        # type: () -> None
        if self._process is not None:
            self._process.terminate()
            self._process.join() # Not sure if redundant

    @staticmethod
    def _run_analysis(data, result_queue):
        # type: (Data, Queue) -> None
        # WARNING: This runs in a different process!
        try:
            identifier = data.focused_packet.identifier

            bodies = np.array([
                struct.unpack("<Q", p.data.ljust(8, b"\x00"))[0]
                for p in data.packets
            ], dtype=np.uint64)

            sizes = set(p.length for p in data.packets)

            if len(sizes) != 1:
                raise Exception(
                    "Can't process identifier {}, whose packet sizes differ."
                    .format(identifier)
                )

            size = list(sizes)[0]
            show_plots = False

            with TemporaryDirectory(prefix="scapy_revdbc_") as output_directory:
                analysis_result = analyze_identifier(
                    identifier,
                    bodies,
                    size,
                    output_directory,
                    show_plots
                )

            analysis_result = analysis_result._replace(
                # Database objects can not be pickled sadly
                restored_dbc=analysis_result.restored_dbc.as_dbc_string()
            )

            result_queue.put(Success(value=analysis_result))
        except BaseException as e:
            result_queue.put(Error(reason=e))

        result_queue.close()
        result_queue.join_thread()

    def _rerun_analysis(self):
        # type: () -> None
        if self._current_data is not None and not self._analysis_running:
            self._start_analysis(self._current_data)
            self._update_views()

    def _wait_for_analysis(self, result_queue):
        # type: (Queue) -> None
        # WARNING: This runs in a different thread!
        self._process.join()
        try:
            last_result = result_queue.get(False)

            if isinstance(last_result, Success):
                last_result = Success(value=last_result.value._replace(
                    restored_dbc=cantools.database.load_string(
                        last_result.value.restored_dbc,
                        database_format='dbc'
                    )
                ))

            self._last_result = last_result
        except Empty:
            self._last_result = None
        self._emit('msg_to_main_thread', 'call', self._update_views)

    @property
    def _analysis_running(self):
        # type: () -> bool
        return self._process is not None and self._process.is_alive()

    def _get_success_result(self):
        # type: () -> Optional[Success]
        if (
            self._current_data is not None and
            not self._analysis_running and
            isinstance(self._last_result, Success)
        ):
            return self._last_result
        
        return None

    def _get_message(self):
        # type: () -> Optional[Message]
        success_result = self._get_success_result()

        if self._current_data is None or success_result is None:
            return None

        identifier = self._current_data.focused_packet.identifier

        return success_result \
            .value \
            .restored_dbc \
            .get_message_by_frame_id(identifier)

    def _save(self):
        # type: () -> None
        save_path = os.path.abspath(os.path.expandvars(os.path.expanduser(
            self._save_path_edit.get_edit_text()
        )))

        message = self._get_message()
        if message is None:
            self._emit('notification', "No message to be saved.")
        else:
            try:
                # Create the directory path leading to the file to create
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

                # Create the file
                with open(save_path, "x"): pass

                # Save the messsage to the newly created file
                cantools.database.dump_file(Database(
                    messages=[message]
                ), save_path, database_format='dbc')

                self._emit('notification', "File written.")
            except BaseException as e:
                self._emit('notification', "Saving failed: {}".format(e))

    def _update_views(self):
        # type: () -> None
        cls = self.__class__

        # There are three pieces of state this plugin holds:
        # - the current data for analysis
        # - whether the analysis is currently running or not
        # - the result of the last analysis that was completed, if at least one
        #   analysis was completed
        
        # TODO: Add state "Analysis Obsolete" for when new packets have arrived
        # after an analysis was successful
        # Update the status text
        if self._current_data is None:
            self._status_text.set_text("No CAN packet selected.")
        else:
            if self._analysis_running:
                self._status_text.set_text("Analysis Running...")
            else:
                if isinstance(self._last_result, Success):
                    self._status_text.set_text("Analysis Done")

                elif isinstance(self._last_result, Error):
                    self._status_text.set_text("Analysis Failed")
                    # TODO: Additional information about the failure
                    # (via popup probably)

                else:
                    self._status_text.set_text("<unknown state>")

        # Update the packet statistic widgets
        success_result = self._get_success_result()
        if self._current_data is None or success_result is None:
            self._graph.original_widget = urwid.SolidFill()
        else:
            # TODO: Use the data transferred via success_result
            message_details = MessageDetailsData([ bytearray(packet.data) for packet in self._current_data.packets ])
            message_details.set_detailed_message_information()
            message_details.create_graph()
            message_details.create_bit_correlation()

            self._graph.original_widget = message_details.graph

        # Update the DBC message widgets
        message = self._get_message()
        if message is None:
            self._ascii_art_text.set_text("")

            if len(self._signal_table_walker) > 0:
                # Disconnect the 'modified' signal before updating the signal
                # table walker.
                urwid.disconnect_signal(
                    self._signal_table_walker,
                    'modified',
                    self._update_views
                )

                del self._signal_table_walker[:]

                # When the focus of the signal table changes, update the UI to
                # highlight the focused signal in the ASCII art.
                urwid.connect_signal(
                    self._signal_table_walker,
                    'modified',
                    self._update_views
                )
        else:
            focused_signal_letter = None # type: Optional[str]

            focused_row = self._signal_table.focus # type: Optional[urwid.Columns]
            if focused_row is not None:
                letter_column_index = \
                    cls \
                        .TABLE_COLUMN_LABELS \
                        .index(cls.LETTER_COLUMN_LABEL)

                letter_text = focused_row.contents[letter_column_index][0] # type: urwid.Text
                focused_signal_letter = letter_text.get_text()[0]

            ascii_art, signal_letter_mapping = message_layout_string(
                message,
                highlight=focused_signal_letter
            )

            self._ascii_art_text.set_text(ascii_art)

            if self._signal_table_walker_state is not message:
                self._signal_table_walker_state = message

                # Disconnect the 'modified' signal before updating the signal
                # table walker.
                urwid.disconnect_signal(
                    self._signal_table_walker,
                    'modified',
                    self._update_views
                )

                del self._signal_table_walker[:]

                # The table header
                self._signal_table_walker.append(urwid.Columns([
                    (width, urwid.Text(label))
                    for label, width
                    in cls.TABLE_COLUMNS
                ], dividechars=cls.TABLE_COLUMN_DIVIDECHARS))

                for signal, letter in sorted(
                    signal_letter_mapping.items(),
                    key=lambda x: x[1]
                ):
                    self._signal_table_walker.append(self._build_table_row(
                        message,
                        signal,
                        letter
                    ))

                # When the focus of the signal table changes, update the UI to
                # highlight the focused signal in the ASCII art.
                urwid.connect_signal(
                    self._signal_table_walker,
                    'modified',
                    self._update_views
                )

            # Decode the current packet and update the signal decoded column
            # accordingly
            signal_values_decoded = message.decode(
                self._current_data.focused_packet.data
            )

            for index, signal in enumerate(map(lambda x: x[0], sorted(
                signal_letter_mapping.items(),
                key=lambda x: x[1]
            ))):
                index += 1 # To account for the header row

                row = self._signal_table_walker[index] # type: urwid.Columns

                decoded_column_index = \
                    cls \
                        .TABLE_COLUMN_LABELS \
                        .index(cls.DECODED_COLUMN_LABEL)

                decoded_text = row.contents[decoded_column_index][0] # type: urwid.Text
                decoded_text.set_text("{} {}".format(
                    signal_values_decoded[signal.name],
                    signal.unit or ""
                ))

    def _build_table_row(self, message, signal, letter):
        # type: (Message, Signal, str) -> urwid.Columns
        cls = self.__class__

        # TODO: Verify all inputs

        def message_updated(message):
            # type: (Message) -> None
            message.refresh(strict=True)
            self._update_views()

        # Label
        def update_signal_label(message, signal, widget, text):
            # type: (Message, Signal, urwid.Edit, str) -> None
            signal.name = text
            message_updated(message)

        signal_label_edit = urwid.Edit(edit_text=signal.name, wrap='clip')
        urwid.connect_signal(signal_label_edit, 'change',
                             update_signal_label, weak_args=(message, signal))
        
        # Signed?
        def update_signal_signed(message, signal, widget, checked):
            # type: (Message, Signal, urwid.Checkbox, bool) -> None
            widget.set_label("yes" if checked else "no")
            signal.is_signed = checked
            message_updated(message)

        signal_signed_checkbox = urwid.CheckBox(
            "yes" if signal.is_signed else "no",
            state=signal.is_signed
        )
        urwid.connect_signal(signal_signed_checkbox, 'change',
                             update_signal_signed, weak_args=(message, signal))
        
        # Float?
        def update_signal_float(message, signal, widget, checked): # TODO: Update the other inputs accurdingly
            # type: (Message, Signal, urwid.Checkbox, bool) -> None
            widget.set_label("yes" if checked else "no")
            signal.is_float = checked
            message_updated(message)

        signal_float_checkbox = urwid.CheckBox(
            "yes" if signal.is_float else "no",
            state=signal.is_float
        )
        urwid.connect_signal(signal_float_checkbox, 'change',
                             update_signal_float, weak_args=(message, signal))

        # Offset
        def update_signal_offset(message, signal, widget, old_text):
            # type: (Message, Signal, urwid.FloatEdit, str) -> None
            signal.offset = widget.value() or 0 # TODO: Use decimal here?
            message_updated(message)

        signal_offset_edit = FloatEdit( # TODO: This doesn't work correctly :(
            default=signal.decimal.offset,
            preserveSignificance=False
        )
        urwid.connect_signal(signal_offset_edit, 'postchange',
                             update_signal_offset, weak_args=(message, signal))

        # Scale
        def update_signal_scale(message, signal, widget, old_text):
            # type: (Message, Signal, urwid.FloatEdit, str) -> None
            signal.scale = widget.value() or 0 # TODO: Use decimal here?
            message_updated(message)

        signal_scale_edit = FloatEdit( # TODO: This doesn't work correctly :(
            default=signal.decimal.scale,
            preserveSignificance=False
        )
        urwid.connect_signal(signal_scale_edit, 'postchange',
                             update_signal_scale, weak_args=(message, signal))

        # Minimum
        def update_signal_minimum(message, signal, widget, old_text):
            # type: (Message, Signal, urwid.FloatEdit, str) -> None
            signal.minimum = widget.value() or 0 # TODO: Use decimal here?
            message_updated(message)

        signal_minimum_edit = FloatEdit( # TODO: This doesn't work correctly :(
            default=signal.decimal.minimum,
            preserveSignificance=False
        )
        urwid.connect_signal(signal_minimum_edit, 'postchange',
                             update_signal_minimum, weak_args=(message, signal))

        # Maximum
        def update_signal_maximum(message, signal, widget, old_text):
            # type: (Message, Signal, urwid.FloatEdit, str) -> None
            signal.maximum = widget.value() or 0 # TODO: Use decimal here?
            message_updated(message)

        signal_maximum_edit = FloatEdit( # TODO: This doesn't work correctly :(
            default=signal.decimal.maximum,
            preserveSignificance=False
        )
        urwid.connect_signal(signal_maximum_edit, 'postchange',
                             update_signal_maximum, weak_args=(message, signal))

        # Unit
        def update_signal_unit(message, signal, widget, text):
            # type: (Message, Signal, urwid.Edit, str) -> None
            signal.unit = None if text == "" else text
            message_updated(message)

        signal_unit_edit = urwid.Edit(edit_text=signal.unit or "", wrap='clip')
        urwid.connect_signal(signal_unit_edit, 'change',
                             update_signal_unit, weak_args=(message, signal))

        # Label -> Column mapping
        column_widgets = {
            cls.LETTER_COLUMN_LABEL: urwid.Text(letter),
            cls.LABEL_COLUMN_LABEL: signal_label_edit,
            cls.SIGNED_COLUMN_LABEL: signal_signed_checkbox,
            cls.FLOAT_COLUMN_LABEL: signal_float_checkbox,
            cls.OFFSET_COLUMN_LABEL: signal_offset_edit,
            cls.SCALE_COLUMN_LABEL: signal_scale_edit,
            cls.MINIMUM_COLUMN_LABEL: signal_minimum_edit,
            cls.MAXIMUM_COLUMN_LABEL: signal_maximum_edit,
            cls.UNIT_COLUMN_LABEL: signal_unit_edit,
            cls.DECODED_COLUMN_LABEL: urwid.Text("")
        }

        # Table rows
        return urwid.Columns([
            (width, column_widgets[label]) for label, width in cls.TABLE_COLUMNS
        ], dividechars=cls.TABLE_COLUMN_DIVIDECHARS)