#!/usr/bin/env python3
from cyber_frost_harness.cli import main


raise SystemExit(main(["analyze-run", *__import__("sys").argv[1:]]))
