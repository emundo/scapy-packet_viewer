# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=protected-access, invalid-name

import six

from scapy.packet import Raw
from scapy.config import conf

from scapy_packet_viewer.row_formatter import RowFormatter


"""
With default columns
"""


def test_init_test1():
    rw = RowFormatter()
    assert rw.basecls is None
    assert len(rw.columns) == 3  # default columns NO, TIME, REPR
    assert rw._format_string == "{NO:5.5} {TIME:11.11} {REPR}"
    assert rw._time == -1.0
    assert len(rw._id_map.items()) == 0


def test_header_string1():
    rw = RowFormatter()
    assert rw.get_header_string() == "NO    TIME        REPR"


def test_format_method1():
    rw = RowFormatter()
    p1 = Raw(b"\xde\xad\xbe\xef")
    p1.time = 42.0
    assert rw.format(p1)[:18] == "0     0.0         "
    p2 = Raw(b"\xde\xad\xbe\xef")
    p2.time = 43.0
    assert rw.format(p2)[:18] == "1     1.0         "
    p3 = Raw(b"\xde\xad\xbe\xef")
    p3.time = 43.5
    assert rw.format(p3)[:18] == "2     1.5         "


"""
With column "rawval" instead of "repr"
Given via config
"""


def test_init_test2():
    conf.contribs["packet_viewer_columns"] = dict()
    conf.contribs["packet_viewer_columns"]["Raw"] = [("rawval", 10, bytes)]
    rw = RowFormatter(basecls=Raw)
    assert rw.basecls == Raw
    assert len(rw.columns) == 3  # default columns NO, TIME
    print(rw._format_string)
    assert rw._format_string == "{NO:5.5} {TIME:11.11} {rawval}"
    assert rw._time == -1.0
    assert len(rw._id_map.items()) == 0
    assert rw.get_header_string() == "NO    TIME        RAWVAL"


def test_format_method2():
    conf.contribs["packet_viewer_columns"] = dict()
    conf.contribs["packet_viewer_columns"]["Raw"] = [("rawval", 10, bytes)]
    rw = RowFormatter(basecls=Raw)
    p1 = Raw(b"\xde\xad\xbe\xef")
    p1.time = 42.0
    if six.PY3:
        assert rw.format(p1)[:28] == "0     0.0         b\'\\xde\\xad"
    else:
        assert rw.format(p1)[:22] == "0     0.0         " + str(b'\xde\xad\xbe\xef')
    p2 = Raw(b"deadbeef")
    p2.time = 43.0
    if six.PY3:
        assert rw.format(p2)[:28] == "1     1.0         b'deadbeef"
    else:
        assert rw.format(p2)[:26] == "1     1.0         deadbeef"
    p3 = Raw(b"deadbeef")
    p3.time = 43.5
    assert rw.format(p3)[:18] == "2     1.5         "


"""
With column "rawval" instead of "repr"
Given via argument to RowFormatter
"""


def test_init_test3():
    columns = [("rawval", 10, bytes)]
    rw = RowFormatter(columns=columns)
    assert rw.basecls is None
    assert len(rw.columns) == 1  # default columns NO, TIME
    assert rw._format_string == "{rawval}"
    assert rw._time == -1.0
    assert len(rw._id_map.items()) == 0


def test_header_string3():
    columns = [("rawval", 10, bytes)]
    rw = RowFormatter(columns=columns)
    assert rw.get_header_string() == "RAWVAL"


def test_format_method3():
    columns = [("rawval", 10, bytes)]
    rw = RowFormatter(columns=columns)
    p = Raw(b"\xde\xad\xbe\xef")
    if six.PY3:
        assert rw.format(p)[:10] == "b\'\\xde\\xad"
    else:
        assert rw.format(p) == b'\xde\xad\xbe\xef'
    p = Raw(b"deadbeef")
    if six.PY3:
        assert rw.format(p)[:10] == "b'deadbeef"
        assert rw.format(p)[:11] == "b'deadbeef'"
    else:
        assert rw.format(p) == "deadbeef"
