#!/usr/bin/env python3
"""
SentinelBit Desktop System Tray Companion (#100)
Provides quick system tray access to status, open vault, and lock.
"""
import webbrowser
import sys

def main():
    print("🛡️ SentinelBit Desktop Companion")
    print("Öffne SentinelBit Web-Tresor...")
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    main()
