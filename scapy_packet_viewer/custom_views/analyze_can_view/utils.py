# SPDX-License-Identifier: GPL-2.0-only

from typing import cast, List

import numpy as np


def count_bit_flips(bodies: List[bytes], size: int) -> List[int]:
    """
    Args:
        bodies: The bodies to analyze.
        size: The number of bits in each body. All bodies must have the same bit size.

    Returns:
        The absolute TAV, i.e. for each bit position the absolute number of bit flips.
    """

    bodies_np = np.array(bodies, dtype=np.uint64)

    if size < 1:
        raise ValueError("Bodies must consist of at least one bit.")
    if size > 64:
        raise ValueError("Bodies must consist of 64 bits at most.")

    tav = np.zeros(size, dtype=np.uint64)
    for bit in np.arange(size):
        bits = (bodies_np >> bit) & 1
        tav[bit] = np.sum(bits[1:] ^ bits[:-1])
    return cast(List[int], tav.tolist())


def calculate_bit_flip_correlation(bodies: List[bytes], size: int) -> List[float]:
    """
    Args:
        bodies: The bodies to analyze.
        size: The number of bits in each body. All bodies must have the same bit size.

    Returns:
        The Bit-Correlation-Over-Time. Like the derivative of the TAV, this metric relates adjacent bit
        positions, thus the entry "0" belongs to the relation between bit positions 0 and 1. Note that entries
        might be nan (= not a number), in case at least one of the correlated bits is constant. For example,
        if bit 4 is constant, the entries "3" and "4" will be nan, because the correlation with a constant bit
        is undefined.
    """

    bodies_np = np.array(bodies, dtype=np.uint64)

    # Free parameters!
    bcot_max_samples = 64 * 1024
    convolution_length = max(min(bodies_np.shape[0], bcot_max_samples) // 200, 64)

    if size < 1:
        raise ValueError("Bodies must consist of at least one bit.")
    if size > 64:
        raise ValueError("Bodies must consist of 64 bits at most.")

    bodies_np = bodies_np[:bcot_max_samples]

    # Note: this code works with temporary Python list, which are potential bottlenecks, but the
    # lists only have one entry per bit position (minus one), so the worst case is 63 entries per
    # list, which should not be an issue.
    # Note: Variable names are chosen as per the paper that defines this algorithm.
    b = bodies_np[1:] ^ bodies_np[:-1]  # pylint: disable=invalid-name

    b_t = np.array([ ((b >> col) & 1) for col in np.arange(size) ], dtype=np.uint8)
    v_t = np.ones((size, convolution_length), dtype=np.uint8)
    c_t = np.array([ np.convolve(b_t[row], v_t[row]) for row in np.arange(size) ])
    bcot = np.array([ np.corrcoef(c_t[row], c_t[row + 1])[1][0] for row in np.arange(size - 1) ])

    return cast(List[float], bcot.astype(np.float64).tolist())
