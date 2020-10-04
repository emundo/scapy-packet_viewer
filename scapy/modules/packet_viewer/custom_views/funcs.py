import math
from itertools import tee

from typing import List, Tuple, Optional


def pairwise(iterable):
    # s -> (s0,s1), (s1,s2), (s2, s3), ...
    first, second = tee(iterable)
    next(second, None)
    return zip(first, second)


def variance(
    values,  # type: List[float]
    is_sorted=False,  # type: bool
):
    # type: (...) -> float
    # If the caller knows it is already sorted
    # we do not need to waste time here.
    if len(values) < 2:
        return 0

    if not is_sorted:
        values.sort()

    values = [t2 - t1 for t1, t2 in pairwise(values)]

    mean = sum(values) / (len(values) or 1)
    numerator = sum([(t - mean) ** 2 for t in values])
    return numerator / len(values)


def byte_flips(
    all_data,  # type: List[bytes]
):
    # type: (...) -> Optional[List[int]]
    # We assume that all data has the same length
    if not all_data:
        return None

    length = len(all_data[0])
    try:
        flips = data_flips(all_data, length)
        return flips
    except IndexError as excpt:
        print("Could not calculate flips. Probably got "
              "messages with different length but same id")
        print(excpt)
        return None


def bit_flips(
    all_data,  # type: List[bytes]
):
    # type: (...) -> Optional[List[int]]
    if not all_data:
        return None

    all_data_in_bits = []
    for data in all_data:
        all_data_in_bits.append("".join(format(byte, "08b") for byte in data))

    length = len(all_data_in_bits[0])
    try:
        flips = data_flips(all_data_in_bits, length)
        return flips
    except IndexError as excpt:
        print("Could not calculate flips. "
              "Probably got messages with different length but same id")
        print(excpt)
        return None


def data_flips(
    all_data, length  # type: int
):
    # type: (...) -> List[int]

    """ This method takes a list of iterable data, of same length,
    and counts the data changes for each position of the data."""
    flips = [0] * length
    prev_data = list(all_data[0])  # type: List[int]
    for data in all_data[1:]:
        for i in range(length):
            if data[i] != prev_data[i]:
                flips[i] += 1
            prev_data[i] = data[i]
    return flips


def average(
    values,  # type: List[float]
):
    # type: (...) -> float

    if not values:
        return 0
    return float(sum(values)) / len(values)


# from https://stackoverflow.com/q/3949226/2050020
def pearson_corr_coeff(
    values_x,  # type: List[float]
    values_y,  # type: List[float]
):
    # Check both lists have the same length and are not empty
    if values_x and len(values_x) != len(values_y):
        return None
    number_values = len(values_x)
    average_values_x = average(values_x)
    average_values_y = average(values_y)
    sum_deviation_prod = 0  # type: float
    sum_value_x_deviation_square = 0  # type: float
    sum_value_y_deviation_square = 0  # type: float
    for idx in range(number_values):
        value_x_deviation = values_x[idx] - average_values_x
        value_y_deviation = values_y[idx] - average_values_y
        sum_deviation_prod += value_x_deviation * value_y_deviation
        sum_value_x_deviation_square += value_x_deviation * value_x_deviation
        sum_value_y_deviation_square += value_y_deviation * value_y_deviation
    if sum_value_x_deviation_square == 0 or sum_value_y_deviation_square == 0:
        return None
    return sum_deviation_prod / math.sqrt(sum_value_x_deviation_square *
                                          sum_value_y_deviation_square)


def bit_flips_for_correlation(
    all_data_in_bits,  # type: List[str]
    length_payload,  # type:  int
    nr_messages,  # type:  int
):
    # type: (...) -> Optional[List[List[int]]]

    all_bit_flips = [[0] * (nr_messages - 1)] * length_payload  # type: List[List[int]]
    prev_data = []  # type: List[str]
    try:
        for idx, data in enumerate(all_data_in_bits):
            if not prev_data:
                for i in range(length_payload):
                    prev_data.append(data[i])
                continue
            for i in range(length_payload):
                # data[i] returns byte as int
                if data[i] != prev_data[i]:
                    all_bit_flips[i][idx - 1] += 1
                prev_data[i] = data[i]
        return all_bit_flips
    # pylint: disable=broad-except
    except Exception as excpt:
        print("Could not calculate flips. "
              "Probably got messages with different length but same id")
        print(excpt)
        return None


def bit_flip_correlation(
    all_data,  # type: List[bytes]
):
    # type: (...) -> Optional[List[float]]

    # TODO: for simplicity only successive bits wil be looked at
    if not all_data and len(all_data) < 2:
        return None
    all_data_in_bits = []
    # Needed to fill inn leading zeros
    for data in all_data:
        all_data_in_bits.append("".join(format(byte, "08b") for byte in data))
    length_payload = len(all_data_in_bits[0])
    nr_messages = len(all_data)
    all_bit_flips = bit_flips_for_correlation(all_data_in_bits,
                                              length_payload,
                                              nr_messages)
    correlations = []  # type: List[float]
    if not all_bit_flips:
        return correlations

    # pylint: disable=consider-using-enumerate
    for idx in range(len(all_bit_flips)):
        if idx == 0:
            continue
        correlations.append(pearson_corr_coeff(all_bit_flips[idx - 1],
                                               all_bit_flips[idx]))

    return correlations
