"""Stdlib selftests for the small staged-file privacy check."""
import contextlib
import io
import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_public_files as check


class PublicFileTests(unittest.TestCase):
    def test_private_paths_and_public_defaults(self):
        for path in (".env", "reports/session.json", "docs/s1-evidence/result.json",
                     "config.local.json", "key.pem", "capture.pcap", "dist/app.exe",
                     "sample.sqlite3-wal", "file:Zone.Identifier", "diagnostic-evidence.json",
                     "losshound_report_sample.txt", "losshound_report_sample.json",
                     "Losshound-ISP-Report-24h.pdf"):
            with self.subTest(path=path):
                self.assertIn("private-file", [i[2] for i in check.scan(path, b"")])
        for path in ("config.default.json", "tests/fixture.json", "assets/losshound.ico",
                     "Losshound.spec", "SECURITY.md"):
            with self.subTest(path=path):
                self.assertEqual(check.scan(path, b"{}"), [])

    def test_strong_secrets_have_no_test_exemption(self):
        for payload in ("gh" + "p_" + "a" * 32, "-----BEGIN " + "PRIVATE KEY-----",
                        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----", "AS" + "IA" + "A" * 16):
            for path in ("tests/fixture.py", "assets/sample.png", "assets/sample.ico"):
                with self.subTest(kind=payload[:2], path=path):
                    self.assertTrue(check.scan(path, payload.encode()))

    def test_only_narrow_synthetic_url_fixtures_pass(self):
        self.assertEqual(check.scan("tests/fixture.py", b"https://" + b"user:secret@" + b"example.com/"), [])
        for host, password, path in (("example.com.attacker.net", "secret", "tests/fixture.py"),
                                      ("real-service.net", "secret", "tests/fixture.py"),
                                      ("example.com", "not-a-placeholder", "tests/fixture.py"),
                                      ("example.com", "secret", "src/example.py")):
            payload = ("https://user:" + password + "@" + host).encode()
            with self.subTest(host=host, path=path):
                self.assertIn("credential-url", [i[2] for i in check.scan(path, payload)])

    def test_home_and_contact_and_credential_literal(self):
        home = "C:" + chr(92) + "Users" + chr(92) + "fixture"
        self.assertTrue(check.scan("sample.txt", home.encode()))
        mail = "person" + "@" + "real-service.net"
        self.assertIn("contact-email", [i[2] for i in check.scan("sample.txt", mail.encode())])
        payload = json.dumps({"pass" + "word": "constructed-value"}).encode()
        self.assertIn("credential-literal", [i[2] for i in check.scan("sample.json", payload)])

    def test_index_blob_used_and_deleted_files_not_read(self):
        sha = b"a" * 40
        responses = {
            ("ls-files", "--stage", "-z"): b"100644 " + sha + b" 0\tsrc/example.py\0",
            ("diff", "--cached", "--name-only", "--diff-filter=ACM", "--no-renames", "-z"): b"src/example.py\0",
            ("cat-file", "blob", sha.decode()): b"safe indexed content",
        }
        with mock.patch.object(check, "git", side_effect=lambda *a: responses[a]) as calls:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(check.main([]), 0)
            self.assertEqual(calls.call_count, 3)

    def test_redacted_failure_output(self):
        secret = "gh" + "p_" + "a" * 32
        sha = "a" * 40
        def fake_git(*args):
            if args[0] == "ls-files":
                return ("100644 " + sha + " 0\tsample.txt\0").encode()
            return secret.encode()
        output = io.StringIO()
        with mock.patch.object(check, "git", side_effect=fake_git):
            with contextlib.redirect_stdout(output):
                self.assertEqual(check.main(["--all-tracked"]), 1)
        self.assertNotIn(secret, output.getvalue())
        self.assertIn("provider-token", output.getvalue())

    def test_git_read_failure_and_unmerged_index_fail_closed(self):
        for value in (RuntimeError("private stderr"), b"100644 " + b"a" * 40 + b" 1\tfile.py\0"):
            output = io.StringIO()
            kwargs = {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}
            with mock.patch.object(check, "git", **kwargs):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(check.main([]), 2)
            self.assertNotIn("private stderr", output.getvalue())


if __name__ == "__main__":
    unittest.main()
