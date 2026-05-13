import unittest

from server import security_status_server as server


class ScheduleTests(unittest.TestCase):
    def test_daily_calendar(self):
        schedule, errors = server.normalize_scan_schedule({
            "enabled": "on",
            "frequency": "daily",
            "weekday": "sun",
            "hour": "22",
            "minute": "0",
            "randomized_delay_minutes": "15",
        })
        self.assertEqual(errors, [])
        self.assertEqual(schedule["on_calendar"], "*-*-* 22:00:00")
        self.assertTrue(schedule["enabled"])

    def test_weekly_calendar(self):
        schedule, errors = server.normalize_scan_schedule({
            "enabled": "true",
            "frequency": "weekly",
            "weekday": "mon",
            "hour": "1",
            "minute": "5",
            "randomized_delay_minutes": "0",
        })
        self.assertEqual(errors, [])
        self.assertEqual(schedule["on_calendar"], "Mon *-*-* 01:05:00")

    def test_parse_exclude_dirs_rejects_paths(self):
        self.assertEqual(server.parse_exclude_dirs("_sem-uso, site_old, ../bad, logs"), ["_sem-uso", "site_old", "logs"])


if __name__ == "__main__":
    unittest.main()
