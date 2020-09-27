from typing import List

from urwid import BarGraph, GraphVScale, Columns


class YScale(GraphVScale):
    """
    Vertical Scala of a Graph 3 values: zero, top and half of top
    """

    def __init__(
        self,
        scale,  # type: List[float]
        top,  # type: int
    ):
        labels = [[y, str(y)] for y in scale]
        super(YScale, self).__init__(labels, top)


class Graph(BarGraph):
    """
    Bar-graph in blue.
    """

    def __init__(
        self,
        graph_data,  # type: List[List[float]]
        top,  # type: int
        scale,  # type: List[float]
    ):
        super(Graph, self).__init__(["", "bg 1", "bg 2"],
                                    hatt=["", "bg 1 line",
                                          "bg 2 line"])

        is_even = True

        for index, _ in enumerate(graph_data):
            if is_even:
                graph_data[index] = [0, graph_data[index][0]]
                is_even = False
            else:
                is_even = True
        self.set_data(graph_data, top, scale)


class GraphView(Columns):
    def __init__(
        self,
        graph_data,  # type: List[List[float]]
        top,  # type: int
    ):
        scale = [top * 0.25, top * 0.5, top * 0.75]
        y_scale = YScale(scale, top)
        graph = Graph(graph_data, top, scale)
        y_scale_space = max([len(str(y)) for y in scale]) + 1
        super(GraphView, self).__init__([(y_scale_space, y_scale), graph])
