# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Tim Henkes <tim.henkes@e-mundo.de>
# This program is published under a GPLv2 license

from collections import namedtuple
from multiprocessing import Process, Queue
from queue import Empty
import struct
from tempfile import TemporaryDirectory
from threading import Thread
from typing import List, Optional, Union

from scapy.layers.can import CAN
from scapy.packet import Packet
from scapy.modules.packet_viewer.details_view import DetailsView

# TODO: Correct import order? Also human-readable output if the package is
# missing?
import cantools
import numpy as np
from revdbc import analyze_identifier
from urwid import Button, Columns, Filler, Frame, Padding, Text


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
    rerun_analysis_label = "Rerun Analysis"

    def __init__(self):
        # type: () -> None
        self._current_data = None # type: Optional[Data]
        self._process = None # type: Optional[Process]
        self._last_result = None # type: Optional[Union[Success, Error]]

        self._left = Filler(Padding(Text(""), align="center", width="pack"))
        self._right = Filler(Padding(Text("_tav heatmap here_"), align="center", width="pack"))

        super(AnalyzeCANView, self).__init__(Frame(Columns([
            self._left,
            self._right
        ], dividechars=3), footer=Padding(Button(
            self.rerun_analysis_label,
            on_press=lambda _: self._rerun_analysis()
        ), align="center", width=len(self.rerun_analysis_label)+4)))

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
        current_data = self._current_data
        analysis_running = self._process is not \
            None and self._process.is_alive()

        if current_data is not None and not analysis_running:
            self._start_analysis(self._current_data)
            self._update_views()

    def _wait_for_analysis(self, result_queue):
        # type: (Queue) -> None
        # WARNING: This runs in a different thread!
        self._process.join()
        try:
            self._last_result = result_queue.get(False)
        except Empty:
            self._last_result = None
        self._emit("msg_to_main_thread", "call", self._update_views)

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

        if current_data is None:
            self._left.base_widget.set_text("No CAN packet selected.")
        else:
            if analysis_running:
                self._left.base_widget.set_text("Analysis running...")
            else:
                if isinstance(last_analysis_result, Success):
                    analysis_result = last_analysis_result.value
                    analysis_result = analysis_result._replace(
                        restored_dbc=cantools.database.load_string(
                            analysis_result.restored_dbc,
                            database_format="dbc"
                        )
                    )

                    message_dbc = analysis_result \
                        .restored_dbc \
                        .get_message_by_frame_id(self._current_data.identifier)

                    self._left.base_widget.set_text(message_dbc.layout_string(
                        signal_names=False
                    ))

                elif isinstance(last_analysis_result, Error):
                    self._left.base_widget.set_text("Analysis failed: {}".format(last_analysis_result.reason))

                else:
                    self._left.base_widget.set_text("<unknown state>")
