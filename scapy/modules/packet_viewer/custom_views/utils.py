from typing import List, Union, Tuple, Optional

from urwid import Text


def create_flips_heat_map(
    flips,  # type: Optional[List[int]]
    name,  # type: str
):
    # type: (...) -> Text
    if not flips:
        return Text([("default_bold", name), ": could not be generated"])

    max_flips = max(flips)  # type: int

    all_flips_text = [("default_bold", name)]  # type: List[Union[Tuple[str, str], str]]
    for flip in flips:
        if flip == 0:
            layout = "green"
        elif flip == max_flips:
            layout = "bold-red"
        elif flip <= max_flips / 2:
            layout = "bold-yellow"
        else:
            layout = "bold-orange"
        all_flips_text.append((layout, str(flip)))
        all_flips_text.append(" | ")

    return Text(all_flips_text)
