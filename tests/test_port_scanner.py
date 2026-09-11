from __future__ import annotations

import json
import socket
import sys
import threading
import unittest
from argparse import ArgumentTypeError
from contextlib import closing
from contextlib import redirect_stdout
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import port_scanner  # noqa: E402


class ValidationTests(unittest.TestCase):
    def test_valid_port_accepts_boundaries(self) -> None:
        self.assertEqual(port_scanner.valid_port("1"), 1)
        self.assertEqual(port_scanner.valid_port("65535"), 65_535)

    def test_valid_port_rejects_out_of_range_value(self) -> None:
        with self.assertRaises(ArgumentTypeError):
            port_scanner.valid_port("0")

    def test_main_rejects_reversed_range(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as context:
                port_scanner.main(
                    ["127.0.0.1", "--start-port", "10", "--end-port", "1"]
                )
        self.assertEqual(context.exception.code, 2)

    def test_parser_accepts_optional_output_and_scan_modes(self) -> None:
        args = port_scanner.build_parser().parse_args(
            ["127.0.0.1", "--banners", "--randomize", "--json"]
        )
        self.assertTrue(args.banners)
        self.assertTrue(args.randomize)
        self.assertTrue(args.json_output)


class ScannerTests(unittest.TestCase):
    def test_detects_a_local_listening_port(self) -> None:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            result = port_scanner.scan_port(
                "127.0.0.1", socket.AF_INET, port, timeout=0.5
            )

        self.assertTrue(result.is_open)
        self.assertEqual(result.port, port)

    def test_reports_a_closed_local_port(self) -> None:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
            server.bind(("127.0.0.1", 0))
            unused_port = server.getsockname()[1]

        result = port_scanner.scan_port(
            "127.0.0.1", socket.AF_INET, unused_port, timeout=0.5
        )
        self.assertFalse(result.is_open)

    def test_reads_an_unsolicited_local_banner(self) -> None:
        banner = b"SSH-2.0-TestServer\r\n"

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def send_banner() -> None:
                connection, _ = server.accept()
                with connection:
                    connection.sendall(banner)

            worker = threading.Thread(target=send_banner)
            worker.start()
            result = port_scanner.grab_banner(
                "127.0.0.1", socket.AF_INET, port, timeout=0.5
            )
            worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(result, "SSH-2.0-TestServer")

    def test_json_mode_emits_parseable_json_only(self) -> None:
        expected_result = port_scanner.ScanResult(
            port=22,
            is_open=True,
            service="ssh",
            banner="SSH-2.0-TestServer",
        )
        output = StringIO()

        with patch("port_scanner.scan_ports", return_value=[expected_result]):
            with redirect_stdout(output):
                exit_code = port_scanner.main(
                    [
                        "127.0.0.1",
                        "--start-port",
                        "22",
                        "--end-port",
                        "22",
                        "--json",
                    ]
                )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["ports_tested"], 1)
        self.assertEqual(document["open_ports"][0]["port"], 22)


if __name__ == "__main__":
    unittest.main()
