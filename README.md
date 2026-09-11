# Python TCP Port Scanner

An educational command-line TCP connect scanner built with Python's standard
`socket` library. It scans a selected port range, prints open ports as they are
found, and reports a timestamped summary.

> Only scan systems that you own or have explicit permission to test.

## Features

- Accepts an IPv4 address, IPv6 address, or host name
- Scans a configurable inclusive TCP port range
- Reports open ports in real time with common service names when available
- Can passively read short service banners from services that greet first
- Can randomize the scan order for detection-pattern experiments
- Can produce machine-readable JSON output
- Uses bounded concurrency and configurable connection timeouts
- Prints start/finish timestamps, duration, and a summary
- Uses only the Python standard library

## Requirements

- Python 3.10 or newer

## Run it

Start with your own computer:

```powershell
python port_scanner.py 127.0.0.1
```

Scan a smaller range:

```powershell
python port_scanner.py 127.0.0.1 --start-port 20 --end-port 443
```

Adjust the timeout and concurrency for a permitted lab host:

```powershell
python port_scanner.py 192.0.2.10 --start-port 1 --end-port 1024 --timeout 1 --workers 50
```

`192.0.2.10` is a documentation-only example address; replace it with an
authorized target.

Optionally read banners that a service sends immediately after connection:

```powershell
python port_scanner.py 127.0.0.1 --start-port 1 --end-port 1024 --banners
```

Produce JSON suitable for saving or processing with another program:

```powershell
python port_scanner.py 127.0.0.1 --start-port 1 --end-port 1024 --json
```

Randomize the order for an authorized lab exercise about scanner detection:

```powershell
python port_scanner.py 127.0.0.1 --start-port 1 --end-port 1024 --randomize
```

Show all options:

```powershell
python port_scanner.py --help
```

## Run the tests

From this directory:

```powershell
python -m unittest discover -s tests -v
```

The tests open a temporary listening socket only on the local loopback
interface. They do not scan another computer.

## How it works

For each port, the scanner attempts a complete TCP connection using
`socket.connect_ex()`. A successful connection indicates that a service is
accepting TCP connections on that port. Closed, filtered, and timed-out ports
are not listed as open. With `--banners`, the scanner makes a second connection
and reads up to 256 bytes that the service offers without prompting; it never
sends application data. It does not attempt to bypass security controls.

## Limitations

- This is a TCP connect scanner, not a SYN/stealth scanner.
- A firewall may silently drop probes, making scans take longer.
- Service names are best-effort labels based on the local operating system's
  service database, not proof of which software is listening.
- Results are a point-in-time observation and may change.
