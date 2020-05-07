import collections
from cvescan import __main__ as main
import logging
import pytest

Args = collections.namedtuple('Args', 'silent, verbose')

def test_set_output_verbosity_info():
    args = Args(silent=False, verbose=False)
    logger = main.set_output_verbosity(args)

    assert logger.level == logging.INFO

def test_set_output_verbosity_silent():
    args = Args(silent=True, verbose=False)
    logger = main.set_output_verbosity(args)
    assert len(logger.handlers) == 1
    assert type(logger.handlers[0]) == type(logging.NullHandler())

def test_set_output_verbosity_debug():
    args = Args(silent=False, verbose=True)
    logger = main.set_output_verbosity(args)

    assert logger.level == logging.DEBUG
