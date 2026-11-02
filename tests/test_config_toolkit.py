import json
import tempfile
import unittest
from pathlib import Path

from src.config_toolkit import checksum, compare, generate_report, process, redact, validate


class ToolkitTests(unittest.TestCase):
    def test_detect_change(self):
        self.assertTrue(generate_report("hostname A\n", "hostname B\n", "r1")["changed"])

    def test_no_change(self):
        self.assertFalse(generate_report("hostname A\n", "hostname A\n", "r1")["changed"])

    def test_validation(self):
        config = "hostname R1\nip ssh version 2\nlogging host 192.0.2.10\n transport input ssh\n"
        self.assertTrue(all(validate(config).values()))

    def test_missing_rule(self):
        self.assertFalse(validate("hostname R1\n")["ssh_version_2"])

    def test_diff(self):
        self.assertIn("+new", compare("old\n", "new\n"))

    def test_redaction(self):
        raw = "hostname R1\nusername admin secret 9 sensitive-example\n"
        self.assertNotIn("sensitive-example", redact(raw))

    def test_checksum(self):
        self.assertEqual(checksum("abc"), checksum("abc"))
        self.assertNotEqual(checksum("abc"), checksum("abcd"))

    def test_output_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old, new = root / "old.txt", root / "new.txt"
            old.write_text("hostname R1\n", encoding="utf-8")
            new.write_text("hostname R2\n", encoding="utf-8")
            result = process(old, new, root / "out", "example")
            self.assertTrue(result["changed"])
            self.assertTrue((root / "out" / "changes.diff").exists())
            data = json.loads((root / "out" / "validation_report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["device"], "example")


if __name__ == "__main__":
    unittest.main()
