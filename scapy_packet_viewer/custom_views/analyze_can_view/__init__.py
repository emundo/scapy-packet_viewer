# SPDX-License-Identifier: GPL-2.0-only

# Check for dependencies that are specific to this custom view
try:
    import cantools
    import numpy
    import revdbc
except ImportError as e:
    raise ImportError(
        "The dependencies of the CAN analysis view are not included in the minimal installation of"
        " scapy-packet_viewer. Please install scapy-packet_viewer[full] to include them in the installation."
    ) from e

from .analyze_can_view import AnalyzeCANView
