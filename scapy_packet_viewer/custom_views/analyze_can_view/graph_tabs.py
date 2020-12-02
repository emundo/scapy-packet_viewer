# SPDX-License-Identifier: GPL-2.0-only

from enum import auto, Enum
from typing import Any, List

import urwid


class GraphTab(Enum):
    DataOverTime = auto()
    BitFlips = auto()
    BitFlipCorrelation = auto()

    def __str__(self) -> str:  # pylint: disable=inconsistent-return-statements
        # Sadly pylint does not seem to understand that all possible cases are covered below.
        if self is GraphTab.DataOverTime:
            return "Data Over Time"
        if self is GraphTab.BitFlips:
            return "Bit Flips"
        if self is GraphTab.BitFlipCorrelation:
            return "Bit Flip Correlation"


class GraphTabs(urwid.Columns):
    urwid_signals = [ 'selection_changed' ]

    def __init__(self) -> None:
        """
        Note: selection_changed is not emitted for the initial selection.
        """
        cls = self.__class__
        urwid.register_signal(cls, cls.urwid_signals)

        # Get the list of tabs to provide
        graph_tabs = list(GraphTab)

        # Start by selecting the first tab (no signal will be emitted for this one)
        self._graph_tab = graph_tabs[0]

        radiobutton_list: List[Any] = []
        super().__init__([
            ('weight', 1, urwid.Padding(urwid.RadioButton(
                radiobutton_list,
                str(graph_tab),
                on_state_change=lambda _, state, graph_tab=graph_tab: self._on_state_change(graph_tab, state)
            ), align='center', width=len(str(graph_tab)) + 4)) for graph_tab in graph_tabs
        ], dividechars=1)

    def _on_state_change(self, graph_tab: GraphTab, state: bool) -> None:
        if state:
            self._graph_tab = graph_tab
            urwid.emit_signal(self, 'selection_changed')

    @property
    def graph_tab(self) -> GraphTab:
        return self._graph_tab
