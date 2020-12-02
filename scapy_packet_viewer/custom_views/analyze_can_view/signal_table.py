# SPDX-License-Identifier: GPL-2.0-only

from decimal import Decimal
import re
from typing import List, Optional, Tuple

from cantools.database.can import Message, Signal
from scapy.packet import Packet
import urwid

from . import message_layout_string as mls
from .decimal_edit import DecimalEdit


class SignalTableRow(urwid.Columns):
    urwid_signals = [ 'message_updated' ]

    C_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,31}$")

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

    def __init__(
        self,
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

    def _update_signal_signed(self, widget: urwid.CheckBox, _old_checked: bool) -> None:
        checked = widget.get_state()
        widget.set_label("yes" if checked else "no")
        self._signal.is_signed = checked
        self._signal_updated()

    def _update_signal_float(self, widget: urwid.CheckBox, _old_checked: bool) -> None:
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

    def _update_signal_offset(self, _widget: DecimalEdit, value: Optional[Decimal]) -> None:
        if value is None:
            # This can never happen, it is just here to satisfy the type checker.
            value = Decimal(1)

        self._signal.decimal.offset = value
        self._signal.offset = float(value)
        self._signal_updated()

    def _update_signal_scale(self, _widget: DecimalEdit, value: Optional[Decimal]) -> None:
        if value is None:
            # This can never happen, it is just here to satisfy the type checker.
            value = Decimal(0)

        self._signal.decimal.scale = value
        self._signal.scale = float(value)
        self._signal_updated()

    def _update_signal_bounds(self) -> None:
        minimum = self._signal_minimum_edit.value
        maximum = self._signal_maximum_edit.value

        # Only update the signal's bounds if the minimum is smaller than the maximum (or one or both is not
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

    focus: Optional[SignalTableRow]

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

    def update(
        self,
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
