# SPDX-License-Identifier: GPL-2.0-only

from multiprocessing import Process, Queue as create_multiprocessing_queue
from multiprocessing.queues import Queue as MultiprocessingQueue
import os
from queue import Empty
import struct
from tempfile import TemporaryDirectory
from threading import Thread
from typing import cast, Any, Dict, List, NamedTuple, Optional, TYPE_CHECKING, Union

import cantools
from cantools.database.can import Database, Message
import numpy
import revdbc
from scapy.layers.can import CAN
from scapy.packet import Packet
import urwid

from scapy_packet_viewer.details_view import DetailsView
from . import message_layout_string as mls
from . import utils
from .graph_tabs import GraphTab, GraphTabs
from .graphs import SignalValueGraph, SimpleBarGraph
from .signal_table import SignalTable


class Data(NamedTuple):
    focused_packet: Packet
    packets: List[Packet]


class Success(NamedTuple):
    value: revdbc.AnalysisResult


class Error(NamedTuple):
    reason: BaseException


class AnalysisResult(NamedTuple):
    packets: List[Packet]
    result: Union[Success, Error]


# The type Queue is generic in the stubs but not at runtime.
# https://mypy.readthedocs.io/en/stable/common_issues.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
if TYPE_CHECKING:
    ResultQueueBase = MultiprocessingQueue[Union[Success, Error]]  # pylint: disable=unsubscriptable-object
else:
    ResultQueueBase = MultiprocessingQueue


class ResultQueue(ResultQueueBase):
    pass


class AnalyzeCANView(DetailsView):
    """
    Custom view exclusively for CAN packets which shows the results of the structural analysis as performed by
    the external package "revdbc" and allows editing and saving the restored DBC message structures.
    """

    action_name = "Analyze CAN"
    palette = SignalValueGraph.PALETTE + SimpleBarGraph.PALETTE

    RERUN_ANALYSIS_BUTTON_LABEL = "Rerun Analysis"
    SAVE_BUTTON_LABEL = "Save DBC to:"
    DEFAULT_SAVE_PATH = "~/analyze_can/restored.dbc"

    def __init__(self) -> None:
        cls = self.__class__

        self._current_data: Optional[Data] = None
        self._process: Optional[Process] = None
        self._result_cache: Dict[int, AnalysisResult] = {}

        self._ascii_art_text = urwid.Text("")
        self._graph = urwid.WidgetPlaceholder(urwid.SolidFill())
        self._graph_tabs = GraphTabs()
        self._save_path_edit = urwid.Edit(edit_text=cls.DEFAULT_SAVE_PATH, wrap='clip')
        self._signal_table = SignalTable()
        self._status_text = urwid.Text("")

        urwid.connect_signal(self._signal_table, 'focus_changed', self._update_views)
        urwid.connect_signal(self._signal_table, 'message_updated', self._update_views)
        urwid.connect_signal(self._graph_tabs, 'selection_changed', self._update_views)

        # Callback for the "Rerun Analysis" button
        def rerun_analysis(_: Any) -> None:
            if not self._analysis_running:
                self._start_analysis()
                self._update_views()

        super().__init__(urwid.Columns([
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
                        (len(cls.SAVE_BUTTON_LABEL) + 4, urwid.Button(
                            cls.SAVE_BUTTON_LABEL,
                            on_press=lambda _: self._save()
                        )),
                        ('weight', 1, self._save_path_edit)
                    ], dividechars=1)),
                    ('pack', urwid.Padding(
                        urwid.Button(
                            cls.RERUN_ANALYSIS_BUTTON_LABEL,
                            on_press=rerun_analysis
                        ),
                        align='left',
                        width=(len(cls.RERUN_ANALYSIS_BUTTON_LABEL) + 4)
                    ))
                ]))
            ])),
            (SignalTable.TABLE_WIDTH + 1, urwid.Padding(
                urwid.Pile([
                    ('pack', urwid.Divider()),
                    ('weight', 1, urwid.Padding(
                        self._signal_table,
                        align='left',
                        width=SignalTable.TABLE_WIDTH
                    )),
                    ('pack', urwid.Divider()),
                    ('pack', self._graph_tabs),
                    ('weight', 1, self._graph)
                ]),
                align='center',
                right=1
            ))
        ], dividechars=1, min_width=40))

    def update_packets(self, focused_packet: Packet, all_packets: List[Packet]) -> None:
        if isinstance(focused_packet, CAN):
            packets_to_analyze = list(filter(
                lambda p: isinstance(p, CAN) and p.identifier == focused_packet.identifier,
                all_packets
            ))

            self._current_data = Data(focused_packet=focused_packet, packets=packets_to_analyze)

            # Only trigger a new analysis in case there is no cached result for that identifier. Triggering an
            # analysis on any change to the packet list would trigger a new analysis on every incoming packet
            # for that identifier, which might be annoying. Still, changes to the packet list are stored to
            # _current_data, so that a manually restarted analysis has access to the most recent list.
            if focused_packet.identifier not in self._result_cache:
                self._start_analysis()
        else:
            self._abort_analysis()
            self._current_data = None

        self._update_views()

    def _start_analysis(self) -> None:
        """
        (Re-)start the analysis.
        """
        data = self._current_data

        self._abort_analysis()

        # Yes, the following code is starting both a process and a thread.
        #
        # Threads:
        # - are subject to the GIL (probably not a big problem here)
        # - can't be terminated without horrible hacks
        #
        # Processes:
        # - can't share (complex) state with the main program and are thus unable to refresh the UI
        #
        # The main thread:
        # - may obviously not be blocked
        #
        # The only somewhat bareable solution I can think of is doing the following: A process is started to
        # run the analysis, posting the result of the analysis into a queue. A thread is started which
        # blockingly waits for the process to terminate, followed by reading the result from the queue and
        # updating the UI.

        result_queue: ResultQueue = cast(ResultQueue, create_multiprocessing_queue())

        self._process = Process(target=self._run_analysis, args=(data, result_queue))
        self._process.start()

        Thread(
            target=self._wait_for_analysis,
            args=(result_queue, data),
            # The daemon flag makes the thread automatically terminate when the main thread/process
            # terminates.
            daemon=True
        ).start()

    def _abort_analysis(self) -> None:
        if self._process is not None:
            self._process.terminate()
            self._process.join()  # Not sure if redundant

    @staticmethod
    def _run_analysis(data: Data, result_queue: ResultQueue) -> None:
        # WARNING: This runs in a different process!
        try:
            identifier = data.focused_packet.identifier

            bodies = numpy.array([
                struct.unpack("<Q", packet.data.ljust(8, b"\x00"))[0]
                for packet
                in data.packets
            ], dtype=numpy.uint64)

            sizes = set(packet.length for packet in data.packets)

            if len(sizes) != 1:
                raise Exception("Can't process identifier {}, whose packet sizes differ.".format(identifier))

            size = list(sizes)[0]
            show_plots = False

            with TemporaryDirectory(prefix="scapy_revdbc_") as output_directory:
                analysis_result = revdbc.analyze_identifier(
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
        except BaseException as e:  # pylint: disable=broad-except
            result_queue.put(Error(reason=e))

        result_queue.close()
        result_queue.join_thread()

    def _wait_for_analysis(self, result_queue: ResultQueue, data: Data) -> None:
        # WARNING: This runs in a different thread!

        process = self._process
        if process is None:
            # Better safe than sorry
            return

        identifier = data.focused_packet.identifier

        process.join()
        try:
            result = result_queue.get(False)

            if isinstance(result, Success):
                # Parse the DBC string into a Database object again.
                result = Success(value=result.value._replace(
                    restored_dbc=cantools.database.load_string(
                        result.value.restored_dbc,
                        database_format='dbc'
                    )
                ))

            if isinstance(result, Error):
                # Display a popup with details (from the main thread)
                self._emit(
                    'msg_to_main_thread',
                    'call',
                    lambda: self._emit('notification', "Analysis failed: {}".format(result.reason))
                )

            self._result_cache[identifier] = AnalysisResult(packets=data.packets, result=result)
        except Empty:
            pass

        self._emit('msg_to_main_thread', 'call', self._update_views)

    @property
    def _analysis_running(self) -> bool:
        return self._process is not None and self._process.is_alive()

    def _get_message(self) -> Optional[Message]:
        if self._current_data is None or self._analysis_running:
            return None

        identifier = self._current_data.focused_packet.identifier
        cached_result = self._result_cache.get(identifier, None)

        if cached_result is not None and isinstance(cached_result.result, Success):
            return cached_result.result.value.restored_dbc.get_message_by_frame_id(identifier)

        return None

    def _save(self) -> None:
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
                with open(save_path, "x"):
                    pass

                # Save the message to the newly created file
                cantools.database.dump_file(Database(messages=[ message ]), save_path, database_format='dbc')

                self._emit('notification', "File written.")
            except OSError as e:
                self._emit('notification', "Saving failed: {}".format(e))
            except Exception as e:  # pylint: disable=broad-except
                # Sadly there is no documentation about the exceptions that can be raised by
                # cantools.database.dump_file, thus catching `Exception` is the only option.
                self._emit('notification', "Saving failed: {}".format(e))

    def _update_views(self) -> None:
        # There are three pieces of state this plugin holds:
        # - the current data for analysis
        # - whether the analysis is currently running or not
        # - the cached results of previous analysis runs

        # Update the status text
        if self._current_data is None:
            self._status_text.set_text("No CAN packet selected.")
        else:
            if self._analysis_running:
                self._status_text.set_text("Analysis Running...")
            else:
                cached_result = self._result_cache.get(self._current_data.focused_packet.identifier, None)
                if cached_result is None:
                    self._status_text.set_text("<unknown state>")
                else:
                    obsolete = cached_result.packets != self._current_data.packets
                    obsolete_suffix = " (obsolete)" if obsolete else ""

                    if isinstance(cached_result.result, Success):
                        self._status_text.set_text("Analysis Done{}".format(obsolete_suffix))

                    if isinstance(cached_result.result, Error):
                        self._status_text.set_text("Analysis Failed{}".format(obsolete_suffix))

        # Update all DBC-related widgets
        message = self._get_message()
        if self._current_data is None or message is None:
            self._signal_table.update(None)
            self._ascii_art_text.set_text("")
            self._graph.original_widget = urwid.SolidFill()
        else:
            self._signal_table.update(message, self._current_data.focused_packet)

            focused_row = self._signal_table.focused_row
            focused_signal = None if focused_row is None else focused_row.signal
            focused_letter = None if focused_row is None else focused_row.letter

            self._ascii_art_text.set_text(mls.message_layout_string(message, highlight=focused_letter))

            if focused_signal is None:
                self._graph.original_widget = urwid.SolidFill()
            else:
                decoded_values = [ message.decode(packet.data, decode_choices=False).get(
                    focused_signal.name,
                    None
                ) for packet in self._current_data.packets ]

                raw_values = [ message.decode(packet.data, decode_choices=False, scaling=False).get(
                    focused_signal.name,
                    None
                ) for packet in self._current_data.packets ]

                graph_tab = self._graph_tabs.graph_tab
                graph = None

                if graph_tab is GraphTab.DataOverTime:
                    graph = SignalValueGraph(decoded_values, focused_signal)

                if graph_tab is GraphTab.BitFlips:
                    bit_flips = utils.count_bit_flips(raw_values, focused_signal.length)

                    graph = SimpleBarGraph(
                        bit_flips,
                        "Bit Position",
                        "Total\xA0Flips",
                        max(bit_flips),
                        yprecision=0
                    )

                if graph_tab is GraphTab.BitFlipCorrelation:
                    graph = SimpleBarGraph(
                        utils.calculate_bit_flip_correlation(raw_values, focused_signal.length),
                        "Inter-Bit Position",
                        "Flip\xA0Correlation",
                        1.0,
                        yprecision=1
                    )

                self._graph.original_widget = urwid.LineBox(
                    graph or urwid.SolidFill("X"),
                    str(graph_tab),
                    lline="", rline="", bline="",
                    blcorner="", brcorner="",
                    trcorner=u"─", tlcorner=u"─"
                )
