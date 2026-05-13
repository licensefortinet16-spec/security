import unittest

from reports import generate_reports


class ReportContextTests(unittest.TestCase):
    def test_score_rows_preserve_context_metadata(self):
        findings = [{
            "host_name": "host1",
            "container_name": "web",
            "image": "nginx",
            "severity": "high",
            "type": "network",
            "evidence": "open port",
        }]
        inventory = {
            "hosts": [{
                "containers": [{
                    "host_name": "host1",
                    "name": "web",
                    "image": "nginx",
                    "context": "cliente-a",
                    "context_source": "docker-context",
                    "docker_context": "cliente-a",
                    "docker_context_owner": "root",
                    "docker_endpoint_host": "unix:///var/run/docker.sock",
                }]
            }]
        }
        rows = generate_reports.score_findings(findings, inventory=inventory)
        self.assertEqual(rows[0]["context"], "cliente-a")
        self.assertEqual(rows[0]["context_source"], "docker-context")
        self.assertEqual(rows[0]["docker_context_owner"], "root")


if __name__ == "__main__":
    unittest.main()
