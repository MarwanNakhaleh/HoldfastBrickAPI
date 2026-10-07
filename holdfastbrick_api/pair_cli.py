"""`holdfastbrick-pair` — open a pairing window and print the 6-digit code.

Run this on the Pi (over SSH or a connected screen) when adding a new phone.
The code is valid for 5 minutes and single-use.
"""

from __future__ import annotations

from .auth import open_pairing_window
from .config import settings


def main() -> None:
    code = open_pairing_window()
    minutes = settings.pairing_window_seconds // 60
    print()
    print("  ┌────────────────────────────────────┐")
    print("  │          Holdfast pairing          │")
    print("  │                                    │")
    print(f"  │        Code:  {code[:3]} {code[3:]}              │")
    print("  │                                    │")
    print(f"  │   Enter this in the app within    │")
    print(f"  │   {minutes} minutes. Single use.         │")
    print("  └────────────────────────────────────┘")
    print()


if __name__ == "__main__":
    main()
