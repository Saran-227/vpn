import subprocess
import sys
import unittest
from pathlib import Path

import pandas as pd


class TestAnalyzePCAP(unittest.TestCase):

    PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "realistic_mixed.pcap"
    )

    OUTPUT = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "realistic_mixed_features.csv"
    )

    SCRIPT = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "analyze_pcap.py"
    )

    def test_analyze_pcap_pipeline(self):
        if self.OUTPUT.exists():
            self.OUTPUT.unlink()

        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                str(self.PCAP),
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        self.assertIn("Packets: 15", result.stdout)
        self.assertIn("Flows: 4", result.stdout)
        self.assertIn("Features: 4", result.stdout)

        self.assertTrue(self.OUTPUT.exists())

        df = pd.read_csv(self.OUTPUT)

        self.assertEqual(df.shape, (4, 23))
        self.assertEqual(
            df["protocol"].tolist(),
            ["TCP", "UDP", "ICMP", "ESP"],
        )

        self.assertEqual(
            df["packet_count"].tolist(),
            [4, 4, 3, 4],
        )

        self.assertEqual(
            df["total_bytes"].tolist(),
            [2960, 1412, 340, 3262],
        )


if __name__ == "__main__":
    unittest.main()
