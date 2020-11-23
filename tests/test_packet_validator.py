# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=protected-access, invalid-name

from scapy.layers.can import CAN
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from scapy_packet_viewer.main_window import MainWindow

is_valid_packet = MainWindow.is_valid_packet
globals_dict = globals()


"""
Check if list items are validated properly
"""


def test_list_with_different_value_types_and_all_valid1():
    """
    Integers and string
    """
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, 'test'])", globals_dict)
    assert res is True
    assert set(classes) <= {CAN}


def test_list_with_different_value_types_and_all_valid2():
    """
    Integers and byte-string
    """
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, b'\x01\x02'])", globals_dict)
    assert res is True
    assert set(classes) <= {CAN}


def test_list_with_different_value_types_and_all_valid3():
    """
    Integers
    """
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, 5])", globals_dict)
    assert res is True
    assert set(classes) <= {CAN}


def test_list_with_different_value_types_but_one_invalid():
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, test])", globals_dict)
    assert res is False
    assert set(classes) <= {CAN}


"""
Check if input is parsed properly
"""


def test_connecting_layers():
    res, classes = is_valid_packet(
        "CAN(identifier=0x123, data=[1, 2, 3, 5]) / Raw(b'\x42') / Ether()",
        globals_dict
    )

    assert res is True
    assert set(classes) <= {CAN, Raw, Ether}


def test_second_function_via_binary_operator():
    res, classes = is_valid_packet(
        "CAN(identifier=0x123, data=[1, 2, 3, b'\x01\x02']) and print('p')",
        globals_dict
    )

    assert res is False
    assert set(classes) <= {CAN}


def test_call_of_random_function():
    res, classes = is_valid_packet("Test()", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_printing_py3_style():
    res, classes = is_valid_packet("print('test')", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_printing_py2_style():
    res, classes = is_valid_packet("print 'test'", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_random_letters():
    res, classes = is_valid_packet("asdfadgdsg", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_non_existing_keyword():
    """
    The keywords are not checked so it shouldn't change anything for the validity
    """
    res, classes = is_valid_packet("CAN(idhfghdf=0x123)", globals_dict)
    assert res is True
    assert set(classes) <= {CAN}


"""
Check if common security vulnerabilities are caught
"""


def test_injection():
    res, classes = is_valid_packet("self._emit('info_popup', 'Injected')", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_even_worse_injection():
    res, classes = is_valid_packet("__import__('subprocess').getoutput('rm –rf *')", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_security_vulnerability():
    res, classes = is_valid_packet("''.__class__.__base__", globals_dict)
    assert res is False
    assert set(classes) == set()
