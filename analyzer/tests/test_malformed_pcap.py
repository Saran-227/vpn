import tempfile
import unittest
from pathlib import Path

from analyzer.feature_extractor.packet_reader import read_pcap


class TestMalformedPCAP(unittest.TestCase):

    def test_invalid_pcap_raises_value_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "invalid.pcap"

            pcap_path.write_bytes(
                b"this is not a valid pcap file"
            )

            with self.assertRaises(ValueError):
                list(read_pcap(pcap_path))


if __name__ == "__main__":
    unittest.main()
