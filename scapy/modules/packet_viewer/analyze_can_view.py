# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Tim Henkes <tim.henkes@e-mundo.de>
# This program is published under a GPLv2 license

from collections import namedtuple
from multiprocessing import Process, Queue
import os
from queue import Empty
import struct
from tempfile import TemporaryDirectory
from threading import Thread
from typing import List, Optional, Union

from scapy.layers.can import CAN
from scapy.packet import Packet
from scapy.modules.packet_viewer.details_view import DetailsView
from scapy.modules.packet_viewer.message_layout_string import \
    message_layout_string

# TODO: Correct import order? Also human-readable output any of the packages are
# missing?
import cantools
import numpy as np
from revdbc import analyze_identifier
import urwid


Data = namedtuple("Data", [ "identifier", "packets" ])
Success = namedtuple("Success", [ "value" ])
Error = namedtuple("Error", [ "reason" ])


class AnalyzeCANView(DetailsView):
    # TODO: Should probably cache analysis results and ask before re-running a
    # full analysis
    """
    Custom view exclusively for CAN packets which shows the results of the
    structural analysis as performed by the external package "revdbc".
    """

    # TODO: CAN will be lowercased, is that cool? (I think it's fine)
    action_name = "Analyze CAN"

    RERUN_ANALYSIS_BUTTON_LABEL = "Rerun Analysis"
    SAVE_BUTTON_LABEL = "Save DBC to:"
    DEFAULT_SAVE_PATH = "~/analyze_can/restored.dbc"
    SIGNAL_LABEL_WIDTH = 32

    def __init__(self):
        # type: () -> None
        cls = self.__class__

        self._current_data = None # type: Optional[Data]
        self._process = None # type: Optional[Process]
        self._last_result = None # type: Optional[Union[Success, Error]]

        self._ascii_art_text = urwid.Text("")
        self._dbc_message_signal_value_widget = urwid.Text("_dbc_message_signal_value_widget")
        self._heatmap_widget = urwid.Text("_heatmap_widget")
        self._status_text = urwid.Text("No CAN packet selected.")
        self._save_path_edit = urwid.Edit(
            edit_text=cls.DEFAULT_SAVE_PATH,
            wrap='clip'
        )

        # This pile has to be initialized with something focusable, otherwise
        # the whole widget tree will stay unfocusable even after something
        # focusable has been added to it.
        self._signal_labels_pile = urwid.Pile([ ('pack', urwid.Edit()) ])

        body = urwid.Columns([
            ('weight', 1, urwid.Filler(urwid.Padding(
                self._ascii_art_text,
                align='center',
                width='pack'
            ))),
            ('weight', 1, urwid.Filler(urwid.Padding(
                self._signal_labels_pile,
                align='center',
                width=cls.SIGNAL_LABEL_WIDTH+3
            ))),
            ('weight', 2, urwid.Pile([
                ('weight', 1, urwid.Filler(urwid.Padding(
                    self._heatmap_widget,
                    align='center',
                    width='pack'
                ))),
                ('pack', urwid.Divider()),
                ('weight', 1, urwid.Filler(urwid.Padding(
                    self._dbc_message_signal_value_widget,
                    align='center',
                    width='pack'
                )))
            ]))
        ], dividechars=1)

        footer = urwid.Columns([
            ('weight', 1, urwid.Pile([
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
            ])),
            ('weight', 1, urwid.Filler(urwid.Padding(
                self._status_text,
                align='right',
                width='pack'
            ), valign='bottom'))
        ], dividechars=1, box_columns=[1])

        super(AnalyzeCANView, self).__init__(urwid.Pile([
            ('weight', 1, body),
            ('pack', urwid.Divider()),
            ('pack', footer)
        ]))

    def update_packets(self, focused_packet, all_packets):
        # type: (Packet, List[Packet]) -> None
        if isinstance(focused_packet, CAN):
            identifier_to_analyze = focused_packet.identifier
            packets_to_analyze = list(filter(
                lambda p: (
                    isinstance(p, CAN) and
                    p.identifier == identifier_to_analyze
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
                self._current_data.identifier != identifier_to_analyze

            if run_analysis or self._current_data.packets != packets_to_analyze:
                self._current_data = Data(
                    identifier=identifier_to_analyze,
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
            identifier = data.identifier

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
                # cantools.database.can.Database object can not be pickled sadly
                restored_dbc=analysis_result.restored_dbc.as_dbc_string()
            )

            result_queue.put(Success(value=analysis_result))
        except BaseException as e:
            result_queue.put(Error(reason=e))

        result_queue.close()
        result_queue.join_thread()

    def _rerun_analysis(self):
        # type: () -> None
        current_data = self._current_data
        analysis_running = self._process is not None and \
            self._process.is_alive()

        if current_data is not None and not analysis_running:
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

    def _get_message(self):
        # type: () -> Optional[cantools.database.can.Message]

        current_data = self._current_data
        analysis_running = self._process is not \
            None and self._process.is_alive()
        last_analysis_result = self._last_result

        if (
            current_data is not None and
            not analysis_running and
            isinstance(last_analysis_result, Success)
        ):
            return \
                last_analysis_result \
                    .value \
                    .restored_dbc \
                    .get_message_by_frame_id(current_data.identifier)
        
        return None

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
                cantools.database.dump_file(cantools.database.can.Database(
                    messages=[ message ]
                ), save_path, database_format='dbc')

                self._emit('notification', "File written.")
            except BaseException as e:
                self._emit('notification', "Saving failed: {}".format(e))

    def _update_signal_name(self, message, signal, widget, text):
        # type: (cantools.database.dbc.Message, cantools.database.dbc.Signal, urwid.Edit, str) -> None

        signal.name = text
        message.refresh(strict=True)

        self._update_views()

    def _update_views(self):
        # type: () -> None

        # There are three pieces of state this plugin holds:
        # - the current data for analysis
        # - whether the analysis is currently running or not
        # - the result of the last analysis that was completed, if at least one
        #   analysis was completed
        current_data = self._current_data
        analysis_running = self._process is not \
            None and self._process.is_alive()
        last_analysis_result = self._last_result

        # Update the status text
        if current_data is None:
            self._status_text.set_text("No CAN packet selected.")
        else:
            if analysis_running:
                self._status_text.set_text("Analysis Running...")
            else:
                if isinstance(last_analysis_result, Success):
                    self._status_text.set_text("Analysis Done")

                elif isinstance(last_analysis_result, Error):
                    self._status_text.set_text("Analysis Failed")

                else:
                    self._status_text.set_text("<unknown state>")

        # Update the DBC message widgets
        message = self._get_message()
        if message is None:
            self._ascii_art_text.set_text("")
            self._signal_labels_pile.contents = []
        else:
            ascii_art, signal_letter_mapping = message_layout_string(message)

            self._ascii_art_text.set_text(ascii_art)

            # TODO: Don't clear and re-create everything if the message has not changed.
            self._signal_labels_pile.contents = []

            for signal, letter in sorted(
                signal_letter_mapping.items(),
                key=lambda x: x[1]
            ):
                signal_label_edit = urwid.Edit(
                    caption="{}: ".format(letter),
                    edit_text=signal.name,
                    wrap='clip'
                )

                # TODO: Do those leak?
                urwid.connect_signal(
                    signal_label_edit,
                    "change",
                    self._update_signal_name,
                    weak_args=(message, signal)
                )

                self._signal_labels_pile.contents.append((
                    signal_label_edit,
                    self._signal_labels_pile.options('pack', None)
                ))