import unittest
import os
import shutil
import hashlib
from scanner_engine import MalwareScanner

class TestLogic(unittest.TestCase):
    def setUp(self):
        self.scanner = MalwareScanner()
        self.test_dir = "test_scan_dir_v2"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # 1. Create a Known Bad File (EICAR) - Should match Blacklist
        # But EICAR string hash in code might not match this file if not exact.
        # Let's write the exact content that produces the SHA256 in scanner.
        # "cf8bd9dfddff007f75adf4c2be48005deb30972b522858b5404113aa09673225" is emptiness or something specific?
        # Actually that hash is mostly likely emptiness or "test".
        # Let's dynamically add a new blacklist item for testing.
        
        self.test_malware_content = b"test_malware_blacklist_signature"
        m = hashlib.sha256()
        m.update(self.test_malware_content)
        self.malware_hash = m.hexdigest()
        
        # Inject into scanner instance for testing without modifying source file again
        self.scanner.BLACKLIST.add(self.malware_hash)
        
        with open(os.path.join(self.test_dir, "blacklisted.exe"), 'wb') as f:
            f.write(self.test_malware_content)

        # 2. Create a "Suspicious but Safe" file (Low confidence)
        with open(os.path.join(self.test_dir, "maybe_safe.exe"), 'w') as f:
            f.write("mostly harmless")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_blacklist_detection(self):
        """Test that blacklist file is detected instantly."""
        result = self.scanner.scan_file(os.path.join(self.test_dir, "blacklisted.exe"))
        self.assertEqual(result['status'], 'malware')
        self.assertEqual(result['Type'], 'Known Signature (Blacklist)')
        self.assertEqual(result['confidence'], 100.0)

    def test_threshold_logic(self):
        """Test that low confidence predictions are marked benign."""
        # We need to mock the predict_proba to return, say, 60% malware
        # which should now be considered benign (< 80%).
        
        original_proba = self.scanner.model.predict_proba
        
        def mock_proba(X):
            # Return [0.4, 0.6] -> 40% Benign, 60% Malware
            # Since 60 < 80, it should fallback to Benign.
            return [[0.4, 0.6]]
            
        self.scanner.model.predict_proba = mock_proba
        
        # Scan the "maybe_safe.exe"
        result = self.scanner.scan_file(os.path.join(self.test_dir, "maybe_safe.exe"))
        
        # Should be benign because 60% < 80% threshold
        self.assertEqual(result['status'], 'benign')
        
        # Restore (though instance is destroyed anyway)
        self.scanner.model.predict_proba = original_proba

if __name__ == '__main__':
    unittest.main()
