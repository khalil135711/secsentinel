import unittest
from pathlib import Path

from secsentinel import logdetect

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"


def fail(sec, ip="203.0.113.9", user="root"):
    return f"Nov  7 10:00:{sec:02d} h sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


class ParseTests(unittest.TestCase):
    def test_parses_failed_and_invalid_user(self):
        line = "Nov  7 03:40:15 web01 sshd[2188]: Failed password for invalid user admin from 198.51.100.7 port 40001 ssh2"
        event = logdetect.parse_line(line, 2026)
        self.assertEqual((event.kind, event.user, event.ip), ("fail", "admin", "198.51.100.7"))

    def test_parses_accepted(self):
        line = "Nov  7 03:12:01 web01 sshd[2101]: Accepted publickey for deploy from 192.0.2.10 port 51122 ssh2"
        self.assertEqual(logdetect.parse_line(line, 2026).kind, "success")

    def test_ignores_unrelated_and_garbage(self):
        self.assertIsNone(logdetect.parse_line("not a log line", 2026))
        self.assertIsNone(logdetect.parse_line("Nov  7 03:12:01 h cron[1]: job done", 2026))

    def test_ipv6(self):
        line = "Nov  7 11:30:00 web01 sshd[2700]: Failed password for bob from 2001:db8::1 port 33000 ssh2"
        self.assertEqual(logdetect.parse_line(line, 2026).ip, "2001:db8::1")


class AnalyzeTests(unittest.TestCase):
    def test_burst_detected(self):
        events = logdetect.parse_lines([fail(s) for s in range(0, 10, 2)], 2026)
        report = logdetect.analyze(events, threshold=5, window=60)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].peak_in_window, 5)

    def test_slow_attempts_not_flagged(self):
        lines = [f"Nov  7 {h:02d}:00:00 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
                 for h in range(10, 16)]
        report = logdetect.analyze(logdetect.parse_lines(lines, 2026), threshold=5, window=60)
        self.assertEqual(report.findings, [])

    def test_login_after_burst_is_critical(self):
        lines = [fail(s) for s in range(0, 10, 2)]
        lines.append("Nov  7 10:00:30 h sshd[1]: Accepted password for root from 203.0.113.9 port 22 ssh2")
        report = logdetect.analyze(logdetect.parse_lines(lines, 2026))
        self.assertTrue(report.findings[0].login_after_burst)

    def test_login_before_burst_not_critical(self):
        lines = ["Nov  7 09:00:00 h sshd[1]: Accepted password for root from 203.0.113.9 port 22 ssh2"]
        lines += [fail(s) for s in range(0, 10, 2)]
        report = logdetect.analyze(logdetect.parse_lines(lines, 2026))
        self.assertFalse(report.findings[0].login_after_burst)

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            logdetect.analyze([], threshold=0)

    def test_sample_file(self):
        with open(SAMPLE, encoding="utf-8") as handle:
            events = logdetect.parse_lines(handle, 2026)
        report = logdetect.analyze(events)
        self.assertEqual([f.ip for f in report.findings], ["203.0.113.45"])
        self.assertTrue(report.findings[0].login_after_burst)
        self.assertEqual(report.findings[0].total_failures, 7)


if __name__ == "__main__":
    unittest.main()
