# SPDX-License-Identifier: GPL-2.0-only

from decimal import Decimal, InvalidOperation
from typing import Any, Optional, Tuple

import urwid


class DecimalEdit(urwid.Edit):
    urwid_signals = [ 'valuechange' ]

    # Instance variable annotations for the untyped urwid.Edit class
    edit_text: str
    edit_pos: int

    def __init__(
        self,
        *args: Any,
        caption: str = "",
        initial: Optional[Decimal] = None,
        default: Optional[Decimal] = None,
        **kwargs: Any
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

        unhandled: Optional[str] = super().keypress(size, key)
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
