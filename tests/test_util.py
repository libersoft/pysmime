# -*- coding: utf-8 -*-
#
# tests/test_util.py
# Filip Valder <fvalder@redhat.com>
# http://www.redhat.com
# License: http://www.gnu.org/licenses/gpl.txt

"""
Test `util` functions
"""

from pysmime import util


def test_seed_prng():
    assert util.seed_prng() is True
