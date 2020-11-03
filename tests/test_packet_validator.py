# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=protected-access, invalid-name

from scapy.layers.can import CAN
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from scapy_packet_viewer.main_window import MainWindow

is_valid_packet = MainWindow.is_valid_packet
globals_dict = globals()


# TODO: New category
def test_listwithdifferentvaluetypesbutallvalid1():
    """
    list with different value types but all valid 1
    """
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, 'test'])", globals_dict)
    assert res is True
    assert set(classes) <= set([CAN])


def test_listwithdifferentvaluetypesbutallvalid2():
    """
    list with different value types but all valid 2
    """
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, b'\x01\x02'])", globals_dict)
    assert res is True
    assert set(classes) <= set([CAN])
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, 5])", globals_dict)
    assert res is True
    assert set(classes) <= set([CAN])


def test_listwithdifferentvaluetypesbutoneinvalid():
    """
    list with different value types but one invalid
    """
    res, classes = is_valid_packet("CAN(identifier=0x123, data=[1, 2, 3, test])", globals_dict)
    assert res is False
    assert set(classes) <= set([CAN])


def test_Connectinglayers():
    """
    Connecting layers
    """
    res, classes = is_valid_packet(
        "CAN(identifier=0x123, data=[1, 2, 3, 5]) / Raw(b'\x42') / Ether()",
        globals_dict
    )

    assert res is True
    assert set(classes) <= set([CAN, Raw, Ether])


# TODO: New category
def test_Secondfunctionviabinaryoperator():
    """
    Second function via binary operator
    """
    res, classes = is_valid_packet(
        "CAN(identifier=0x123, data=[1, 2, 3, b'\x01\x02']) and print('p')",
        globals_dict
    )

    assert res is False
    assert set(classes) <= set([CAN])


def test_Callofrandomfunction():
    """
    Call of random function
    """
    res, classes = is_valid_packet("Test()", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_PrintingPy3style():
    """
    Printing Py3 style
    """
    res, classes = is_valid_packet("print('test')", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_PrintingPy2style():
    """
    Printing Py2 style
    """
    res, classes = is_valid_packet("print 'test'", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_Randomletters():
    """
    Random letters
    """
    res, classes = is_valid_packet("asdfadgdsg", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_ifkeywordsexistisnotimportantforvalidity():
    """
    if keywords exist is not important for validity
    """
    res, classes = is_valid_packet("CAN(idhfghdf=0x123)", globals_dict)
    assert res is True
    assert set(classes) <= set([CAN])


def test_Injection():
    """
    Injection
    """
    res, classes = is_valid_packet("self._emit('info_popup', 'Injected')", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_Evenworseinjection():
    """
    Even worse injection
    """
    res, classes = is_valid_packet("__import__('subprocess').getoutput('rm –rf *')", globals_dict)
    assert res is False
    assert set(classes) == set()


def test_Securityvulnerability():
    """
    Security vulnerability
    """
    res, classes = is_valid_packet("''.__class__.__base__", globals_dict)
    assert res is False
    assert set(classes) == set()
