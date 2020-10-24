from decimal import Decimal, InvalidOperation
from enum import Enum, auto
import math
from multiprocessing import Process, Queue
import os
from queue import Empty
import re
import struct
from tempfile import TemporaryDirectory
from threading import Thread
from typing import Dict, List, NamedTuple, Optional, Tuple, Union

import cantools
from cantools.database.can import Database, Message, Signal
import numpy
import revdbc
from scapy.layers.can import CAN
from scapy.packet import Packet
import urwid

from scapy_packet_viewer.details_view import DetailsView
from . import message_layout_string as mls
from . import utils

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


class DecimalEdit(urwid.Edit):
    urwid_signals = [ 'valuechange' ]

    def __init__(self,
        caption: str = "",
        initial: Optional[Decimal] = None,
        default: Optional[Decimal] = None,
        *args, **kwargs
    ) -> None:
        cls = self.__class__
        urwid.register_signal(cls, cls.urwid_signals)

        self._default = default

        super().__init__(caption, "" if initial is None else str(initial), *args, **kwargs)

    def valid_char(self, ch: str) -> bool:
        return len(ch) == 1 and ch.upper() in "0123456789.-"

    def keypress(self, size: Tuple[int], key: str) -> Optional[str]:
        old_edit_text = self.edit_text
        old_edit_pos = self.edit_pos

        unhandled = super().keypress(size, key)
        if unhandled is None:
            # Check whether the text (still) parses as a decimal after applying the keypress and restore the
            # previous text if it does not.
            try:
                self._emit('valuechange', self.value)
            except InvalidOperation:
                self.edit_text = old_edit_text
                self.edit_pos = old_edit_pos

        return unhandled

    @property
    def value(self) -> Optional[Decimal]:
        edit_text = self.edit_text

        # A special case that should be considered valid is just "-" in the input, which happens naturally
        # when attempting to type a negative number from scratch. It is treated as -0 here.
        if edit_text == "-":
            edit_text = "-0"

        return self._default if edit_text == "" else Decimal(edit_text)


class BarGraphContainer(urwid.Pile):
    def __init__(self,
        graph: urwid.Widget,
        xaxis: urwid.Widget,
        xaxis_height: int,
        yaxis: urwid.Widget,
        yaxis_width: int
    ):
        super().__init__([
            ('weight', 1, urwid.Columns([
                (yaxis_width, yaxis),
                ('weight', 1, graph)
            ], dividechars=1)),
            (xaxis_height, urwid.Columns([
                (yaxis_width, urwid.SolidFill()),
                ('weight', 1, urwid.Filler(xaxis))
            ], dividechars=1))
        ])


class YAxisContainer(urwid.Columns):
    def __init__(self, yaxis: urwid.Widget, yaxis_width: int, ylabel: str):
        self._width = yaxis_width + 2

        super().__init__([
            (1, urwid.Filler(urwid.Text(ylabel))),
            (yaxis_width, yaxis)
        ], dividechars=1)

    @property
    def width(self):
        return self._width


class SignalValueGraph(BarGraphContainer):
    PALETTE = [
        ("bar 1", "", "dark blue"),
        ("bar 2", "", "dark cyan")
    ]

    def __init__(self, data: List[float], signal: Signal) -> None:
        # Use minimum and maximum as defined in the signal. If those are not defined, fall back to the minimum
        # and maximum values.
        minimum = signal.minimum if signal.minimum is not None else min(data)
        maximum = signal.maximum if signal.maximum is not None else max(data)

        # To be able to display positive and negative values, two bar graphs are created if needed.
        if minimum >= maximum:
            raise ValueError("The minimum must be smaller than the maximum.")

        # Calculate offset and range of the values to be displayed, both in positive and negative. Note that
        # the following variables can never both be 'None' because of the check above.
        positive_offset = max(minimum, 0) if maximum > 0 else None
        negative_offset = min(maximum, 0) if minimum < 0 else None

        positive_range = None if positive_offset is None else abs(maximum - positive_offset)
        negative_range = None if negative_offset is None else abs(minimum - negative_offset)

        # Calculate the step size for the scale. The bigger of the two ranges is divided into three segments
        # (0%-33%, 33%-67%, 67%-100%) and thus dictates the step size for the smaller range. If only one range
        # is present, that range is instead divided into five segments to make up for the missing range.
        positive_scale = None
        negative_scale = None

        if positive_range is None:
            # Only the negative range exists, divide it into five segments.
            negative_scale = [
                negative_offset - negative_range * 1.0,
                negative_offset - negative_range * 0.8,
                negative_offset - negative_range * 0.6,
                negative_offset - negative_range * 0.4,
                negative_offset - negative_range * 0.2,
                negative_offset - negative_range * 0.0
            ]
        elif negative_range is None:
            # Only the positive range exists, divide it into five segments.
            positive_scale = [
                positive_offset + positive_range * 0.0,
                positive_offset + positive_range * 0.2,
                positive_offset + positive_range * 0.4,
                positive_offset + positive_range * 0.6,
                positive_offset + positive_range * 0.8,
                positive_offset + positive_range * 1.0
            ]
        else:
            # Both ranges exist. Find the bigger one and divide it into three segments to find the step size.
            step_size = max(positive_range, negative_range) / 3

            # Add (up to four) segment separators in positive direction.
            positive_scale = []
            for i in range(4):
                segment_separator = i * step_size

                if segment_separator <= maximum:
                    positive_scale.append(segment_separator)

            # Add (up to four) segment separators in negative direction.
            negative_scale = []
            for i in range(4):
                segment_separator = i * step_size * -1

                if segment_separator >= minimum:
                    negative_scale.insert(0, segment_separator)

            # Note that both scales contain the separator at 0, so the maximum amount of distinct separators
            # is 7, making for one more segment in total than in above cases where only a single range exists.

        # Build the VScales
        positive_vscale_width = None
        negative_vscale_width = None

        positive_vscale = None
        negative_vscale = None

        minimum_label_precision = max(
            signal.decimal.scale.as_tuple().exponent * -1,
            signal.decimal.offset.as_tuple().exponent * -1,
            0 # In case neither scale nor offset have any decimal places
        )

        def label(y):
            # Give one extra digit of precision
            return "{:.{precision}f}".format(y, precision=minimum_label_precision+1)

        if positive_scale is not None:
            positive_vscale_width = max(len(label(y)) for y in positive_scale)
            positive_vscale = urwid.GraphVScale(
                [ [ y - positive_offset, label(y) ] for y in positive_scale ],
                positive_range
            )

        if negative_scale is not None:
            negative_vscale_width = max(len(label(y)) for y in negative_scale)
            negative_vscale = urwid.GraphVScale(
                [ [ y - minimum, label(y) ] for y in negative_scale ],
                negative_range
            )

        vscales_width = max(positive_vscale_width or 0, negative_vscale_width or 0)

        # A little trick is used to achieve the ripple effect of this bar graph:
        # Bars are defined to consist of two different-color segments, but when building the bars, one segment
        # is always set to height 0 while the other segment gets the actual bar height. That way, bars of
        # different colors can be created.
        positive_graph = None
        positive_graph_data = None

        negative_graph = None
        negative_graph_data = None

        if positive_scale is not None:
            positive_graph = urwid.BarGraph([ "", "bar 1", "bar 2" ], hatt=[ "", "bar 1", "bar 2" ])
            positive_graph.set_bar_width(1)

            positive_graph_data = []
            for index, element in enumerate(data):
                element -= positive_offset
                element = max(element, 0)

                if index % 2 == 0:
                    positive_graph_data.append((element, 0))
                else:
                    positive_graph_data.append((0, element))

        if negative_scale is not None:
            # The negative bar effect is achieved by first filling the whole bar with the desired color and
            # then overdrawing the bottom portion of the bar with the background color.
            negative_graph = urwid.BarGraph([ "", "bar 1", "bar 2", "" ], hatt=[ "", "bar 1", "bar 2", "" ])
            negative_graph.set_bar_width(1)

            negative_graph_data = []
            for index, element in enumerate(data):
                element -= minimum
                element = max(element, 0)

                if index % 2 == 0:
                    negative_graph_data.append((negative_range, 0, element))
                else:
                    negative_graph_data.append((0, negative_range, element))

        # Prepare the graphs and scales to be displayed together in piles
        graph_pile = []
        yaxis_pile = []
        any_graph = None

        if positive_graph is not None:
            any_graph = positive_graph
            graph_pile.append(('weight', positive_range, positive_graph))
            yaxis_pile.append(('weight', positive_range, positive_vscale))

        if negative_graph is not None:
            any_graph = negative_graph
            graph_pile.append(('weight', negative_range, negative_graph))
            yaxis_pile.append(('weight', negative_range, negative_vscale))

        xaxis = XAxis(any_graph, "Packet Number", 0, len(data))
        yaxis = YAxisContainer(urwid.Pile(yaxis_pile), vscales_width, "Value")

        offset = 0
        offset_change = 32

        def update():
            if positive_graph is not None and positive_graph_data is not None:
                positive_graph.set_data(
                    positive_graph_data[offset:],
                    positive_range,
                    [ y - positive_offset for y in positive_scale ]
                )

            if negative_graph is not None and negative_graph_data is not None:
                negative_graph.set_data(
                    negative_graph_data[offset:],
                    negative_range,
                    [ y - minimum for y in negative_scale ]
                )

            xaxis.offset = offset

        def scroll_left(_):
            nonlocal offset

            offset = max(offset - offset_change, 0)
            update()

        def scroll_right(_):
            nonlocal offset

            offset = min(offset + offset_change, len(data) - 1)
            update()

        update()

        super().__init__(
            urwid.Pile(graph_pile),
            urwid.Pile([
                ('weight', 1, xaxis),
                ('pack', urwid.Columns([
                    ('weight', 1, urwid.Padding(
                        urwid.Button("scroll left", on_press=scroll_left),
                        align='left',
                        width=len("scroll left")+4
                    )),
                    ('weight', 1, urwid.Padding(
                        urwid.Button("scroll right", on_press=scroll_right),
                        align='right',
                        width=len("scroll right")+4
                    ))
                ]))
            ]),
            xaxis.height + 1,
            yaxis,
            yaxis.width
        )


class XAxis(urwid.Pile):
    def __init__(self, graph: urwid.BarGraph, label: str, offset: int, num_bars: int, num_labels: int = 4):
        if num_labels < 2:
            raise ValueError("A minimum of two axis labels are required.")

        self._graph = graph
        self._offset = offset
        self._num_bars = num_bars
        self._num_labels = num_labels

        self._pointers = urwid.Columns([])
        self._labels = urwid.Columns([])

        super().__init__([
            ('pack', self._pointers),
            ('pack', self._labels),
            ('pack', urwid.Text(label, align='center'))
        ])

    def render(self, size, focus):
        # Hook into the render method and fill pointers/labels dynamically based on the size passed here.

        # calculate_bar_widths doesn't utilize the data at all, it only uses the number of bars
        bar_widths = self._graph.calculate_bar_widths((size[0], self.height), [ None ] * self._num_bars)

        # Get the number of bars that will be displayed by the bar chart and the overall number of columns
        # that will be filled by those bars. Calculating those number this way is required, as configuration
        # on the BarGraph instance can change those values. The actual available width is not relevant.
        num_bars = len(bar_widths)
        width = sum(bar_widths)

        # The labels at min and max are always drawn at the left and right edges of the axis. Additional
        # labels are drawn in between with even spacing.
        num_additional_labels = self._num_labels - 2

        # Find the bars that will receive a label
        labeled_bars = [ 0 ] + [
            round((num_bars * i) / (num_additional_labels + 1)) for i in range(1, num_additional_labels + 1)
        ] + [ num_bars - 1 ]

        # If fewer bars are available than the number of requested labels, drop those overflowing labels.
        # Also if zero bars are available, the code above will add the index -1 to the list, which is removed
        # here.
        labeled_bars = sorted(filter(lambda x: x >= 0 and x < num_bars, set(labeled_bars)))

        # Fill the pointer row
        used_width = 0
        pointer_columns = []

        for label_bar in labeled_bars:
            # Find the position by summing up all bar widths up to the target bar
            label_bar_position = sum(bar_widths[0:label_bar])

            column_content_width = bar_widths[label_bar]
            column_padding_left = max(label_bar_position - used_width, 0)
            column_width = column_padding_left + column_content_width

            pointer_columns.append((
                urwid.Text("^" * column_content_width, align='right'),
                urwid.Columns.options(width_type='given', width_amount=column_width)
            ))

            used_width += column_width

        self._pointers.contents = pointer_columns

        # Fill the label row
        used_width = 0
        label_columns = []

        for label_bar in labeled_bars:
            # Find the position by summing up all bar widths up to the target bar
            label_bar_position = sum(bar_widths[0:label_bar])

            label = str(label_bar + self._offset)

            # Center the label below the pointer(s)
            column_content_width = len(label)
            wanted_space_left = math.ceil((column_content_width - bar_widths[label_bar]) / 2)
            wanted_space_right = math.floor((column_content_width - bar_widths[label_bar]) / 2)
            remaining_space_left = max(label_bar_position - used_width, 0)
            remaining_space_right = width - label_bar_position - 1
            padding_left = remaining_space_left - wanted_space_left
            padding_right = remaining_space_right - wanted_space_right

            if padding_left < 0:
                missing_padding = -padding_left
                padding_left += missing_padding
                padding_right -= missing_padding

            if padding_right < 0:
                missing_padding = -padding_right
                padding_left -= missing_padding
                padding_right += missing_padding

            column_width = padding_left + column_content_width

            label_columns.append((
                urwid.Text(label, align='right'),
                urwid.Columns.options(width_type='given', width_amount=column_width)
            ))

            used_width += column_width

        self._labels.contents = label_columns

        # Now that everything dynamic has been adjusted, render and return the canvas.
        return super().render(size, focus)

    @property
    def height(self):
        return 3
    
    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, offset: int):
        self._offset = offset
        self._invalidate()


class SimpleBarGraph(BarGraphContainer):
    PALETTE = [
        ("bar 1", "", "dark blue"),
        ("bar 2", "", "dark cyan"),
        ("nan", "", "dark red")
    ]

    def __init__(self,
        data: List[Union[int, float]],
        xlabel: str,
        ylabel: str,
        ymax: float,
        num_x_labels: int = 4,
        yprecision: int = 2
    ) -> None:
        def label(y):
            return "{:.{precision}f}".format(y, precision=yprecision)

        yscale = [ ymax * 0.0, ymax * 0.2, ymax * 0.4, ymax * 0.6, ymax * 0.8, ymax * 1.0 ]

        graph_data = []
        for index, element in enumerate(data):
            if math.isnan(element):
                graph_data.append((0, 0, ymax))
            else:
                if index % 2 == 0:
                    graph_data.append((element, 0, 0))
                else:
                    graph_data.append((0, element, 0))

        graph = urwid.BarGraph([ "", "bar 1", "bar 2", "nan" ], hatt=[ "", "bar 1", "bar 2", "nan" ])
        graph.set_data(graph_data, ymax, yscale)
        
        xaxis = XAxis(graph, xlabel, 0, len(data), num_x_labels)
        yaxis = YAxisContainer(
            urwid.GraphVScale([ (y, label(y)) for y in yscale ], ymax),
            max(len(label(y)) for y in yscale),
            ylabel
        )

        super().__init__(graph, xaxis, xaxis.height, yaxis, yaxis.width)


class SignalTableRow(urwid.Columns):
    urwid_signals = [ 'message_updated' ]

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

    TABLE_COLUMN_INFO: List[Tuple[str, int]] = [
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
    ]

    TABLE_COLUMN_LABELS = [ label for label, _ in TABLE_COLUMN_INFO ]
    TABLE_COLUMNS: List[Tuple[str, int]] = [
        # (column label, column width)
        (label, max(len(label), min_width))
        for label, min_width
        in TABLE_COLUMN_INFO
    ]

    TABLE_COLUMN_DIVIDECHARS = 2
    TABLE_ROW_WIDTH = (len(TABLE_COLUMNS) - 1) * TABLE_COLUMN_DIVIDECHARS + sum(w for _, w in TABLE_COLUMNS)

    def __init__(self,
        message: Message,
        signal: Signal,
        letter: str,
        focused_packet: Optional[Packet] = None
    ) -> None:
        cls = self.__class__
        urwid.register_signal(cls, cls.urwid_signals)

        self._message = message
        self._signal = signal
        self._letter = letter

        self._focused_packet: Optional[Packet] = None
        self._decoded_value = urwid.Text("")

        # Label
        signal_label_edit = urwid.Edit(edit_text=signal.name, wrap='clip')
        urwid.connect_signal(signal_label_edit, 'postchange', self._update_signal_label)
        
        # Signed?
        signal_signed_checkbox = urwid.CheckBox("yes" if signal.is_signed else "no", state=signal.is_signed)
        urwid.connect_signal(signal_signed_checkbox, 'postchange', self._update_signal_signed)
        
        # Float?
        signal_float_checkbox = urwid.CheckBox("yes" if signal.is_float else "no", state=signal.is_float)
        urwid.connect_signal(signal_float_checkbox, 'postchange', self._update_signal_float)

        # Offset
        signal_offset_edit = DecimalEdit(initial=signal.decimal.offset, default=Decimal(0), wrap='clip')
        urwid.connect_signal(signal_offset_edit, 'valuechange', self._update_signal_offset)

        # Scale
        signal_scale_edit = DecimalEdit(initial=signal.decimal.scale, default=Decimal(1), wrap='clip')
        urwid.connect_signal(signal_scale_edit, 'valuechange', self._update_signal_scale)

        # Minimum
        self._signal_minimum_edit = DecimalEdit(initial=signal.decimal.minimum, wrap='clip')
        urwid.connect_signal(
            self._signal_minimum_edit,
            'valuechange',
            lambda _widget, _value: self._update_signal_bounds()
        )

        # Maximum
        self._signal_maximum_edit = DecimalEdit(initial=signal.decimal.maximum, wrap='clip')
        urwid.connect_signal(
            self._signal_maximum_edit,
            'valuechange',
            lambda _widget, _value: self._update_signal_bounds()
        )

        # Unit
        signal_unit_edit = urwid.Edit(edit_text=signal.unit or "", wrap='clip')
        urwid.connect_signal(signal_unit_edit, 'postchange', self._update_signal_unit)

        # Label -> Column mapping
        column_widgets = {
            cls.LETTER_COLUMN_LABEL: urwid.Text(letter),
            cls.LABEL_COLUMN_LABEL: signal_label_edit,
            cls.SIGNED_COLUMN_LABEL: signal_signed_checkbox,
            cls.FLOAT_COLUMN_LABEL: signal_float_checkbox,
            cls.OFFSET_COLUMN_LABEL: signal_offset_edit,
            cls.SCALE_COLUMN_LABEL: signal_scale_edit,
            cls.MINIMUM_COLUMN_LABEL: self._signal_minimum_edit,
            cls.MAXIMUM_COLUMN_LABEL: self._signal_maximum_edit,
            cls.UNIT_COLUMN_LABEL: signal_unit_edit,
            cls.DECODED_COLUMN_LABEL: self._decoded_value
        }

        super().__init__(
            [ (width, column_widgets[label]) for label, width in cls.TABLE_COLUMNS ],
            dividechars=cls.TABLE_COLUMN_DIVIDECHARS
        )

        self.update(focused_packet)

    def update(self, focused_packet: Optional[Packet], force: bool = False) -> None:
        if focused_packet is not self._focused_packet or force:
            self._focused_packet = focused_packet

            # Update the "Decoded Value" cell if needed
            if focused_packet is None:
                self._decoded_value.set_text("")
            else:
                self._decoded_value.set_text("{} {}".format(
                    self._message.decode(focused_packet.data).get(self._signal.name, "n.A."),
                    self._signal.unit or ""
                ))

    @property
    def signal(self) -> Signal:
        return self._signal

    @property
    def letter(self) -> str:
        return self._letter

    C_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,31}$")
    @classmethod
    def _validate_c_identifier(cls, text: str) -> bool:
        return cls.C_IDENTIFIER_RE.match(text) is not None

    @classmethod
    def _validate_char_string(cls, text: str) -> bool:
        # All printable characters except for '"' are allowed.
        return text.isprintable() and '"' not in text

    def _signal_updated(self) -> None:
        # Refresh and re-validate the message
        self._message.refresh(strict=True)

        # Force an update
        self.update(self._focused_packet, force=True)

        urwid.emit_signal(self, 'message_updated')
    
    def _update_signal_label(self, widget: urwid.Edit, old_text: str) -> None:
        text = widget.edit_text

        # An empty label is a special case, as it has to be possible to fully delete a label before typing a
        # new one, but an empty label is obviously invalid. The (slightly hacky) solution chosen here is to
        # assume the (valid) signal name "__empty__" instead of an empty label.
        if text == "":
            text = "__empty__"

        if self._validate_c_identifier(text):
            self._signal.name = text
            self._signal_updated()
        else:
            widget.edit_text = old_text

    def _update_signal_signed(self, widget: urwid.CheckBox, old_checked: bool) -> None:
        checked = widget.get_state()
        widget.set_label("yes" if checked else "no")
        self._signal.is_signed = checked
        self._signal_updated()

    def _update_signal_float(self, widget: urwid.CheckBox, old_checked: bool) -> None:
        # TODO: Float signals are kind of a mystery. What about minimum/maximum/scale/offset/signedness etc.
        # when dealing with float signals?
        checked = widget.get_state()

        if checked and self._signal.length not in [ 16, 32, 64 ]:
            # Block setting the float flag if the signal is not of the required bit length.
            # TODO: Some info about the blocking for the user would be cool here
            widget.set_state(False, do_callback=False)
        else:
            widget.set_label("yes" if checked else "no")
            self._signal.is_float = checked
            self._signal_updated()

    def _update_signal_offset(self, widget: DecimalEdit, value: Optional[Decimal]) -> None:
        self._signal.decimal.offset = value
        self._signal.offset = float(value)
        self._signal_updated()

    def _update_signal_scale(self, widget: DecimalEdit, value: Optional[Decimal]) -> None:
        self._signal.decimal.scale = value
        self._signal.scale = float(value)
        self._signal_updated()

    def _update_signal_bounds(self) -> None:
        minimum = self._signal_minimum_edit.value
        maximum = self._signal_maximum_edit.value

        # Only update the signal's bounds if the minimum is smaller thatn the maximum (or one of both is not
        # defined).
        if minimum is None or maximum is None or minimum < maximum:
            self._signal.decimal.minimum = minimum
            self._signal.decimal.maximum = maximum
            self._signal.minimum = None if minimum is None else float(minimum)
            self._signal.maximum = None if maximum is None else float(maximum)
            self._signal_updated()

    def _update_signal_unit(self, widget: urwid.Edit, old_text: str) -> None:
        text = widget.edit_text

        if self._validate_char_string(text):
            self._signal.unit = None if text == "" else text
            self._signal_updated()
        else:
            widget.edit_text = old_text


class SignalTable(urwid.ListBox):
    urwid_signals = [ 'focus_changed', 'message_updated' ]

    TABLE_WIDTH = SignalTableRow.TABLE_ROW_WIDTH

    def __init__(self, message: Optional[Message] = None, focused_packet: Optional[Packet] = None) -> None:
        cls = self.__class__
        urwid.register_signal(cls, cls.urwid_signals)

        self._message: Optional[Message] = None

        super().__init__(urwid.SimpleFocusListWalker([
            # Initialized with just the table header
            urwid.Columns(
                [ (width, urwid.Text(label)) for label, width in SignalTableRow.TABLE_COLUMNS ],
                dividechars=SignalTableRow.TABLE_COLUMN_DIVIDECHARS
            )
        ]))

        self.update(message, focused_packet)

    def _focus_changed(self) -> None:
        urwid.emit_signal(self, 'focus_changed')

    def _message_updated(self) -> None:
        # Simply forward the event
        urwid.emit_signal(self, 'message_updated')

    def update(self,
        message: Optional[Message],
        focused_packet: Optional[Packet] = None,
        force: bool = False
    ) -> None:
        # If the message has changed, update the table
        if message is not self._message or force:
            self._message = message

            # Disconnect the 'modified' signal before updating the table walker, as modification in code
            # triggers events.
            urwid.disconnect_signal(self.body, 'modified', self._focus_changed)

            # Delete all rows except for the header
            del self.body[1:]

            if message is not None:
                # Map signals to letters
                signal_letter_mapping = mls.get_signal_letter_mapping(message)

                # Build the signal rows
                for signal, letter in sorted(signal_letter_mapping.items(), key=lambda x: x[1]):
                    row = SignalTableRow(message, signal, letter)

                    # Get notified about changes to the message
                    urwid.connect_signal(row, 'message_updated', self._message_updated)

                    self.body.append(row)

            # Reconnect the signal as soon as the modifications are done
            urwid.connect_signal(self.body, 'modified', self._focus_changed)

        for row in self.body[1:]:
            row.update(focused_packet)

    @property
    def focused_row(self) -> Optional[SignalTableRow]:
        # Exclude the header by checking for a focus position of 0
        if self.focus is None or self.focus_position == 0:
            return None

        return self.focus


class GraphTab(Enum):
    DataOverTime = auto()
    Bitflips = auto()
    BitflipCorrelation = auto()

    def __str__(self):
        if self is GraphTab.DataOverTime:
            return "Data Over Time"
        if self is GraphTab.Bitflips:
            return "Bitflips"
        if self is GraphTab.BitflipCorrelation:
            return "Bitflip Correlation"


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

        radiobutton_list = []
        super().__init__([
            ('weight', 1, urwid.Padding(urwid.RadioButton(
                radiobutton_list,
                str(graph_tab),
                on_state_change=lambda _, state, graph_tab=graph_tab: self._on_state_change(graph_tab, state)
            ), align='center', width=len(str(graph_tab))+4)) for graph_tab in graph_tabs
        ], dividechars=1)

    def _on_state_change(self, graph_tab: GraphTab, state: bool) -> None:
        if state:
            self._graph_tab = graph_tab
            urwid.emit_signal(self, 'selection_changed')

    @property
    def graph_tab(self) -> GraphTab:
        return self._graph_tab


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
        def rerun_analysis(_):
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
                        (len(cls.SAVE_BUTTON_LABEL)+4, urwid.Button(
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
                        width=len(cls.RERUN_ANALYSIS_BUTTON_LABEL)+4
                    ))
                ]))
            ])),
            (SignalTable.TABLE_WIDTH+1, urwid.Padding(
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

        result_queue = Queue()

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
            self._process.join() # Not sure if redundant

    @staticmethod
    def _run_analysis(data: Data, result_queue: Queue) -> None:
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
        except BaseException as e:
            result_queue.put(Error(reason=e))

        result_queue.close()
        result_queue.join_thread()

    def _wait_for_analysis(self, result_queue: Queue, data: Data) -> None:
        # WARNING: This runs in a different thread!
        identifier = data.focused_packet.identifier

        self._process.join()
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

        if isinstance(cached_result.result, Success):
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
                with open(save_path, "x"): pass

                # Save the messsage to the newly created file
                cantools.database.dump_file(Database(messages=[ message ]), save_path, database_format='dbc')

                self._emit('notification', "File written.")
            except BaseException as e:
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
                try:
                    if graph_tab is GraphTab.DataOverTime:
                        graph = SignalValueGraph(decoded_values, focused_signal)

                    if graph_tab is GraphTab.Bitflips:
                        graph_data = utils.count_bit_flips(raw_values, focused_signal.length)

                        graph = SimpleBarGraph(
                            graph_data,
                            "Bit Position",
                            "Total\xA0Flips",
                            max(graph_data),
                            yprecision=0
                        )

                    if graph_tab is GraphTab.BitflipCorrelation:
                        graph_data = utils.calculate_bitflip_correlation(raw_values, focused_signal.length)

                        graph = SimpleBarGraph(
                            graph_data,
                            "Inter-Bit Position",
                            "Flip\xA0Correlation",
                            1.0,
                            yprecision=1
                        )
                except:
                    pass

                self._graph.original_widget = urwid.LineBox(
                    graph or urwid.SolidFill("X"),
                    str(graph_tab),
                    lline="", rline="", bline="",
                    blcorner="", brcorner="",
                    trcorner=u"─", tlcorner=u"─"
                )