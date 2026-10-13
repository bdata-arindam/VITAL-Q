"""Regression: deallocation of each returned result must follow timer stop."""
import unittest
from timing import checked_measure,timed_call

class TimerTest(unittest.TestCase):
    def test_result_disposal_after_stop(self):
        events=[]
        class Result(dict):
            def __del__(self):events.append('dispose')
        def clock():events.append('clock');return len(events)*1000
        def function():events.append('call');return Result(accepted=True,counts=[1])
        for _ in range(3):
            value,seconds=timed_call(function,clock=clock)
            self.assertEqual(events[-1],'clock')
            del value
            self.assertEqual(events[-1],'dispose')
        self.assertEqual(events,['clock','call','clock','dispose']*3)
    def test_checker_disposes_before_next_call(self):
        live=[]
        class Result(dict):
            def __del__(self):live.pop()
        def function():
            self.assertEqual(live,[]);live.append(1)
            return Result(accepted=True,counts=[1])
        for _ in range(3):checked_measure(function,expected_counts=[1])
        self.assertEqual(live,[])

if __name__=='__main__':unittest.main()
