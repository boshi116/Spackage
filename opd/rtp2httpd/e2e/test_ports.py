"""Keep parallel test workers from allocating each other's listen ports."""

from itertools import pairwise

import pytest
from helpers import worker_port_range


@pytest.mark.parametrize("worker_count", [4, 8, 16, 32])
def test_worker_port_ranges_do_not_overlap(monkeypatch, worker_count):
    monkeypatch.setenv("PYTEST_XDIST_WORKER_COUNT", str(worker_count))
    ranges = []
    for index in range(worker_count):
        monkeypatch.setenv("PYTEST_XDIST_WORKER", f"gw{index}")
        start, end = worker_port_range()
        assert 14000 <= start < end <= 32400
        ranges.append((start, end))
    ordered = sorted(ranges)
    assert all(left[1] <= right[0] for left, right in pairwise(ordered))
