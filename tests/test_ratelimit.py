from __future__ import annotations

import pytest

from kevgate.ratelimit import TokenBucketLimiter


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_burst_then_block_then_refill() -> None:
    clock = Clock()
    lim = TokenBucketLimiter(60, clock=clock)  # 1 token per second, burst 60
    assert all(lim.acquire("k").allowed for _ in range(60))
    blocked = lim.acquire("k")
    assert not blocked.allowed and blocked.retry_after == 1
    clock.t += 1.0
    assert lim.acquire("k").allowed
    assert not lim.acquire("k").allowed


def test_retry_after_reflects_refill_rate() -> None:
    clock = Clock()
    lim = TokenBucketLimiter(2, clock=clock)  # one token every 30 s
    lim.acquire("k")
    lim.acquire("k")
    assert lim.acquire("k").retry_after == 30
    clock.t += 20
    assert lim.acquire("k").retry_after == 10


def test_buckets_are_independent() -> None:
    lim = TokenBucketLimiter(1, clock=Clock())
    assert lim.acquire("a").allowed
    assert not lim.acquire("a").allowed
    assert lim.acquire("b").allowed


def test_tokens_capped_at_capacity() -> None:
    clock = Clock()
    lim = TokenBucketLimiter(2, clock=clock)
    clock.t += 10_000
    assert [lim.acquire("k").allowed for _ in range(3)] == [True, True, False]


def test_eviction_bounds_memory() -> None:
    clock = Clock()
    lim = TokenBucketLimiter(60, clock=clock, max_buckets=3)
    for k in "abc":
        lim.acquire(k)
    clock.t += 120  # all three refilled -> evictable
    lim.acquire("d")
    assert len(lim) == 1
    # When nothing is idle, the oldest bucket goes.
    for k in "ef":
        lim.acquire(k)
    lim.acquire("g")
    assert len(lim) == 3


def test_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        TokenBucketLimiter(0)
