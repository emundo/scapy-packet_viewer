# SPDX-License-Identifier: GPL-2.0-only

import math
from typing import cast, Any, List, Optional, Sequence, Tuple, Union

from cantools.database.can import Signal
import urwid


class BarGraphContainer(urwid.Pile):
    def __init__(
        self,
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
    def width(self) -> int:
        return self._width


class SignalValueGraph(BarGraphContainer):
    PALETTE = [
        ("bar 1", "", "dark blue"),
        ("bar 2", "", "dark cyan")
    ]

    def __init__(self, data: Sequence[float], signal: Signal) -> None:
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

        if positive_range is None and negative_range is not None:
            # Only the negative range exists, divide it into five segments.
            negative_scale = [
                negative_offset - negative_range * 1.0,
                negative_offset - negative_range * 0.8,
                negative_offset - negative_range * 0.6,
                negative_offset - negative_range * 0.4,
                negative_offset - negative_range * 0.2,
                negative_offset - negative_range * 0.0
            ]

        if positive_range is not None and negative_range is None:
            # Only the positive range exists, divide it into five segments.
            positive_scale = [
                positive_offset + positive_range * 0.0,
                positive_offset + positive_range * 0.2,
                positive_offset + positive_range * 0.4,
                positive_offset + positive_range * 0.6,
                positive_offset + positive_range * 0.8,
                positive_offset + positive_range * 1.0
            ]

        if positive_range is not None and negative_range is not None:
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
            0  # In case neither scale nor offset have any decimal places
        )

        def label(y: int) -> str:
            # Give one extra digit of precision
            return "{:.{precision}f}".format(y, precision=(minimum_label_precision + 1))

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
        positive_graph_data: Optional[List[Tuple[float, float]]] = None

        negative_graph = None
        negative_graph_data: Optional[List[Tuple[float, float, float]]] = None

        if positive_scale is not None and positive_range is not None:
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

        if negative_scale is not None and negative_range is not None:
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

        def update() -> None:
            if positive_graph is not None and positive_graph_data is not None and positive_scale is not None:
                positive_graph.set_data(
                    positive_graph_data[offset:],
                    positive_range,
                    [ y - positive_offset for y in positive_scale ]
                )

            if negative_graph is not None and negative_graph_data is not None and negative_scale is not None:
                negative_graph.set_data(
                    negative_graph_data[offset:],
                    negative_range,
                    [ y - minimum for y in negative_scale ]
                )

            xaxis.offset = offset

        def scroll_left(_: Any) -> None:
            nonlocal offset

            offset = max(offset - offset_change, 0)
            update()

        def scroll_right(_: Any) -> None:
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
                        width=(len("scroll left") + 4)
                    )),
                    ('weight', 1, urwid.Padding(
                        urwid.Button("scroll right", on_press=scroll_right),
                        align='right',
                        width=(len("scroll right") + 4)
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

    def render(
        self,
        size: Union[Tuple[()], Tuple[int], Tuple[int, int]],
        focus: bool = False
    ) -> urwid.Canvas:
        # Hook into the render method and fill pointers/labels dynamically based on the size passed here.

        if len(size) == 0:
            raise ValueError("The size tuple must contain at least the available number of columns.")

        columns = cast(Union[Tuple[int], Tuple[int, int]], size)[0]

        # calculate_bar_widths doesn't utilize the data at all, it only uses the number of bars
        bar_widths = self._graph.calculate_bar_widths((columns, self.height), [ None ] * self._num_bars)

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
        labeled_bars = sorted(filter(lambda x: 0 <= x < num_bars, set(labeled_bars)))

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
    def height(self) -> int:
        return 3

    @property
    def offset(self) -> int:
        return self._offset

    @offset.setter
    def offset(self, offset: int) -> None:
        self._offset = offset
        self._invalidate()


class SimpleBarGraph(BarGraphContainer):
    PALETTE = [
        ("bar 1", "", "dark blue"),
        ("bar 2", "", "dark cyan"),
        ("nan", "", "dark red")
    ]

    def __init__(
        self,
        data: Sequence[float],
        xlabel: str,
        ylabel: str,
        ymax: float,
        num_x_labels: int = 4,
        yprecision: int = 2
    ) -> None:
        def label(y: float) -> str:
            return "{:.{precision}f}".format(y, precision=yprecision)

        yscale = [ ymax * 0.0, ymax * 0.2, ymax * 0.4, ymax * 0.6, ymax * 0.8, ymax * 1.0 ]

        graph_data: List[Tuple[float, float, float]] = []
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
