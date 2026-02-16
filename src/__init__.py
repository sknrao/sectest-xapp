"""
O-RAN Near-RT RIC Security Testing xApp

This xApp tests compliance with O-RAN.WG11.TS.SRCS.0-R004-v13.00 Chapter 5.1.3
for Near-RT RIC and xApps security requirements and controls.

Main modules:
- main: Entry point and orchestration
- security_tests: Test modules for different security aspects
- utils: Utility functions for certificates, reporting, and metrics
- xdevsm: State machine for test orchestration
"""

__version__ = "1.0.0"
__author__ = "O-RAN Security Team"
__license__ = "Apache 2.0"

# Package metadata
XAPP_NAME = "security-test-xapp"
XAPP_VERSION = __version__
O_RAN_SPEC = "O-RAN.WG11.TS.SRCS.0-R004-v13.00"
SPEC_CHAPTER = "5.1.3"

__all__ = [
    '__version__',
    'XAPP_NAME',
    'XAPP_VERSION',
    'O_RAN_SPEC',
    'SPEC_CHAPTER'
]