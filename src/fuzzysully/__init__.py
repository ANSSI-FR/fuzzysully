"""
FuzzySully is an OPCUA fuzzer based on Fuzzowski.
It exposes the FuzzySully class plus two enums (OPCUASupportedPolicies and
OPCUAMode) which describe the security policies and the OPCUA modes that are
currently supported by the tool.
FuzzySully is designed to be used through the CLI tool, but it can be used as
a lib by directly instantiating the FuzzySully class.
"""

from .fuzzer import OPCUAMode
from .fuzzysully import FuzzySully, OPCUASupportedPolicies

__version__ = "0.1.0"
