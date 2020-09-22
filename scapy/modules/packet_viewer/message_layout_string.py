from typing import Tuple, Dict

from cantools.database.can.message import Message
from cantools.database.can.signal import Signal
from cantools.database.utils import start_bit

def message_layout_string(message):
    # type: (Message) -> Tuple[str, Dict[Signal, str]]
    """
    This is a copy of the cantools.database.can.message.Message.layout_string
    method, adjusted to the needs of the AnalyzeCANView.

    The output of the original layout_string method (using signal_names=True),
    given a DBC message that consists of 8 bytes and has many signals, is too
    tall (in lines) for the AnalyzeCANView. Setting signal_names=False is not a
    solution, as some sort of association between signals in the ASCII-art and
    signal names is needed.

    This copy of the layout_string method is adjusted to label signals right in
    the signal ASCII-art, using lowercase letters from 'a' to 'z' in place of
    the original signal-starting x's. The mapping between the letters and the
    signals is returned with the ASCII-art string.

    Args:
        message: The message to format.

    Returns:
        The message formatted as ASCII-art, and the mapping between the signals
        and signal letters.
    """

    # Mapping between signals and signal letters
    signal_letter_mapping = {} # type: Dict[Signal, str]

    # Populate the mappings
    next_signal_letter_ord = ord('a')
    for signal in message._signals:
        next_signal_letter = chr(next_signal_letter_ord)
        signal_letter_mapping[signal] = next_signal_letter
        next_signal_letter_ord += 1

    # A string containing all signal letters for convenience
    all_signal_letters = ''.join(signal_letter_mapping.values())

    def format_big():
        signals = []

        for signal in message._signals:
            if signal.byte_order != 'big_endian':
                continue

            # Small modification here to use the signal letter for the tail
            # instead of 'x'
            formatted = start_bit(signal) * '   '
            formatted += '<{}{}'.format(
                (3 * signal.length - 2) * '-',
                signal_letter_mapping[signal]
            )
            signals.append(formatted)

        return signals

    def format_little():
        signals = []

        for signal in message._signals:
            if signal.byte_order != 'little_endian':
                continue

            # Small modification here to use the signal letter for the tail
            # instead of 'x'
            formatted = signal.start * '   '
            formatted += '{}{}<'.format(
                signal_letter_mapping[signal],
                (3 * signal.length - 2) * '-'
            )
            end = signal.start + signal.length

            if end % 8 != 0:
                formatted += (8 - (end % 8)) * '   '

            formatted = ''.join([
                formatted[i:i + 24][::-1]
                for i in range(0, len(formatted), 24)
            ])
            signals.append(formatted)

        return signals

    def format_byte_lines():
        # Signal lines.
        signals = format_big() + format_little()

        if len(signals) > 0:
            length = max([len(signal) for signal in signals])

            if length % 24 != 0:
                length += (24 - (length % 24))

            signals = [
                signal + (length - len(signal)) * ' ' for signal in signals
            ]

        # Signals union line.
        signals_union = ''

        for chars in zip(*signals):
            head = chars.count('<')
            dash = chars.count('-')

            # Modified to detect signal letters as tails instead of 'x'
            tail = sum(chars.count(letter) for letter in all_signal_letters)

            # Little modification of the original code to find the union char
            # more easily
            non_space_chars = list(filter(lambda char: char != ' ', chars))

            if head + dash + tail > 1:
                signals_union += 'X' # TODO: This swallows tails
            else:
                if len(non_space_chars) == 0:
                    signals_union += ' '
                else:
                    signals_union += non_space_chars[0]

        # Split the signals union line into byte lines, 8 bits per
        # line.
        byte_lines = [
            signals_union[i:i + 24]
            for i in range(0, len(signals_union), 24)
        ]

        unused_byte_lines = (message._length - len(byte_lines))

        if unused_byte_lines > 0:
            byte_lines += unused_byte_lines * [24 * ' ']

        # Insert bits separators into each byte line.
        lines = []

        for byte_line in byte_lines:
            line = ''
            prev_byte = None

            for i in range(0, 24, 3):
                byte_triple = byte_line[i:i + 3]

                if i == 0:
                    line += '|'
                elif byte_triple[0] in (' <>' + all_signal_letters):
                    # Detecting signal letters instead of 'x' ^
                    line += '|'
                elif byte_triple[0] == 'X':
                    if prev_byte == 'X':
                        line += 'X'
                    elif prev_byte == '-':
                        line += '-'
                    else:
                        line += '|'
                else:
                    line += '-'

                line += byte_triple
                prev_byte = byte_triple[2]

            line += '|'
            lines.append(line)

        # Add byte numbering.
        number_width = len(str(len(lines))) + 4
        number_fmt = '{{:{}d}} {{}}'.format(number_width - 1)
        a = []

        for number, line in enumerate(lines):
            a.append(number_fmt.format(number, line))

        return a, len(lines), number_width

    def add_header_lines(lines, number_width):
        padding = number_width * ' '

        return [
            padding + '               Bit',
            padding + '',
            padding + '  7   6   5   4   3   2   1   0',
            padding + '+---+---+---+---+---+---+---+---+'
        ] + lines

    def add_horizontal_lines(byte_lines, number_width):
        padding = number_width * ' '
        lines = []

        for byte_line in byte_lines:
            lines.append(byte_line)
            lines.append(padding + '+---+---+---+---+---+---+---+---+')

        return lines

    def add_y_axis_name(lines):
        number_of_matrix_lines = (len(lines) - 3)

        if number_of_matrix_lines < 5:
            lines += (5 - number_of_matrix_lines) * ['     ']

        start_index = 4 + ((number_of_matrix_lines - 4) // 2 - 1)

        if start_index < 4:
            start_index = 4

        axis_lines = start_index * ['  ']
        axis_lines += [' B', ' y', ' t', ' e']
        axis_lines += (len(lines) - start_index - 4) * ['  ']

        return [
            axis_line + line
            for axis_line, line in zip(axis_lines, lines)
        ]

    # All signal name labelling code was removed.
    lines, _, number_width = format_byte_lines()
    lines = add_horizontal_lines(lines, number_width)
    lines = add_header_lines(lines, number_width)
    lines = add_y_axis_name(lines)
    lines = [line.rstrip() for line in lines]

    return '\n'.join(lines), signal_letter_mapping
