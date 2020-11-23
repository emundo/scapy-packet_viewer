# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=protected-access, invalid-name

from collections import OrderedDict

from scapy_packet_viewer.button_bar import ButtonBar, Action

"""
The button bar contains the actions at the bottom of the program.
These tests check for its proper behavior for various actions.
"""


def test_valid_use():
    global_var = 0

    def fun1():
        nonlocal global_var
        global_var = 1

    def fun2():
        nonlocal global_var
        global_var = 2

    def fun3():
        nonlocal global_var
        global_var = 3

    a = Action(["fun1", "fun2", "fun3"], [fun1, fun2, fun3])
    assert "fun1" in a.text
    assert global_var == 0
    a.execute()
    assert "fun2" in a.text
    assert global_var == 1
    a.execute()
    assert "fun3" in a.text
    assert global_var == 2
    a.execute()
    assert "fun1" in a.text
    assert global_var == 3
    a.execute()
    assert "fun2" in a.text
    assert global_var == 1
    a.execute()


def test_invalid_init_more_names():
    exception_caught = False

    def fun1():
        pass

    try:
        Action(["1", "2"], [fun1])
    except AssertionError:
        exception_caught = True

    assert exception_caught


def test_invalid_init_more_functions():
    exception_caught = False

    def fun1():
        pass

    try:
        Action(["1"], [fun1, fun1, fun1])
    except AssertionError:
        exception_caught = True

    assert exception_caught


def test_invalid_init_index_out_of_range():
    exception_caught = False

    def fun1():
        pass

    try:
        Action(["1"], [fun1], state_index=3)
    except AssertionError:
        exception_caught = True

    assert exception_caught


def test_ui_interaction_one_action():
    global_var = 0

    def fun1():
        nonlocal global_var
        global_var = 1

    def fun2():
        nonlocal global_var
        global_var = 2

    def fun3():
        nonlocal global_var
        global_var = 3

    a = Action(["fun1", "fun2", "fun3"], [fun1, fun2, fun3])
    cmds = OrderedDict()
    cmds["f1"] = a
    b = ButtonBar(cmds)

    assert "fun1" in b.widget_list[0].get_label()
    assert global_var == 0

    b.keypress(0, "f1")

    assert "fun2" in b.widget_list[0].get_label()
    assert global_var == 1

    b.keypress(0, "f1")

    assert "fun3" in b.widget_list[0].get_label()
    assert global_var == 2

    b.keypress(0, "f1")

    assert "fun1" in b.widget_list[0].get_label()
    assert global_var == 3

    b.keypress(0, "f1")

    assert "fun2" in b.widget_list[0].get_label()
    assert global_var == 1

    b.keypress(0, "f1")


def test_ui_interaction_two_actions():
    global_var = 0

    def fun1():
        nonlocal global_var
        global_var = 1

    def fun2():
        nonlocal global_var
        global_var = 2

    def fun3():
        nonlocal global_var
        global_var = 3

    a = Action(["fun1", "fun2", "fun3"], [fun1, fun2, fun3])
    c = Action(["foo1", "foo2", "foo3"], [fun1, fun2, fun3])

    cmds = OrderedDict()
    cmds["f1"] = a
    cmds["f2"] = c

    b = ButtonBar(cmds)
    assert global_var == 0
    assert "fun1" in b.widget_list[0].get_label()
    assert "foo1" in b.widget_list[1].get_label()

    b.keypress(0, "f1")
    assert global_var == 1
    assert "fun2" in b.widget_list[0].get_label()
    assert "foo1" in b.widget_list[1].get_label()

    b.keypress(0, "f1")
    assert global_var == 2
    assert "fun3" in b.widget_list[0].get_label()
    assert "foo1" in b.widget_list[1].get_label()

    b.keypress(0, "f2")
    assert global_var == 1
    assert "fun3" in b.widget_list[0].get_label()
    assert "foo2" in b.widget_list[1].get_label()

    b.keypress(0, "f1")
    assert global_var == 3
    assert "fun1" in b.widget_list[0].get_label()
    assert "foo2" in b.widget_list[1].get_label()

    b.keypress(0, "f2")
    assert global_var == 2
    assert "fun1" in b.widget_list[0].get_label()
    assert "foo3" in b.widget_list[1].get_label()

    b.keypress(0, "f2")
    assert global_var == 3
    assert "fun1" in b.widget_list[0].get_label()
    assert "foo1" in b.widget_list[1].get_label()

    b.keypress(0, "f1")
    b.keypress(0, "f2")

    assert global_var == 1
    assert "fun2" in b.widget_list[0].get_label()
    assert "foo2" in b.widget_list[1].get_label()
