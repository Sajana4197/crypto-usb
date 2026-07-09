"""Entry point: `python main.py` launches the CryptoUSB application."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.main import run

if __name__ == "__main__":
    sys.exit(run())
