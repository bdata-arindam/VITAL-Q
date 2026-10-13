"""One verifier call per timer; returned objects are disposed after the stop clock."""
import time

def timed_call(function, *args, clock=time.perf_counter_ns, **kwargs):
    start = clock()
    value = function(*args, **kwargs)
    stop = clock()
    return value, (stop - start) / 1e9

def checked_measure(function, *args, expected_counts=None, **kwargs):
    value, seconds = timed_call(function, *args, **kwargs)
    assert value['accepted']
    if expected_counts is not None:
        assert value['counts'] == expected_counts
    counts = list(value['counts'])
    del value
    return {'seconds': seconds, 'counts': counts, 'accepted': True}
