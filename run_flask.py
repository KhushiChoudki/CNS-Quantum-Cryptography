"""
Flask PQC Bridge — Entry Point
================================
Run this on the Azure VM (or locally for dev):

    python run_flask.py

The bridge listens on 0.0.0.0:5001
Node.js backend at :3000 proxies to this.
"""

import sys
import os

# Allow importing security_engine as a package from project root
sys.path.insert(0, os.path.dirname(__file__))

from security_engine.app import app

if __name__ == "__main__":
    print("=" * 60)
    print(" CNS PQC Security Bridge")
    print(" Algorithm: CRYSTALS-Kyber-512 (NIST FIPS 203)")
    print(" Listening : http://0.0.0.0:5001")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001, debug=False)
