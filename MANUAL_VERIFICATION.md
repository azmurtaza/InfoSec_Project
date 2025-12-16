# Manual Verification Guide for Cloud Reputation Integration

## Quick Verification Checklist

Follow these steps to manually verify the cloud reputation integration is working correctly.

### ✅ Step 1: Verify EICAR Detection (Signature Priority)

**Test:** EICAR test file must always be detected with 100% confidence.

1. Create a file named `eicar.txt` with this exact content:
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```

2. Launch the application:
   ```bash
   python src/gui.py
   ```

3. Navigate to **Scan File** section

4. Browse and select `eicar.txt`

5. **Expected Results:**
   - Status: **THREAT DETECTED** (red)
   - Confidence: **100.00%**
   - Type: **EICAR Test File** or **Known Signature**
   - Cloud analysis: Should NOT appear (signature detection has priority)

**✓ PASS if:** File is detected as malware with 100% confidence
**✗ FAIL if:** File is marked as safe or confidence is not 100%

---

### ✅ Step 2: Verify Benign File Handling

**Test:** Harmless files must not be falsely flagged.

1. Create a file named `test_safe.txt` with this content:
   ```
   This is a harmless text file.
   It contains no malicious content.
   ```

2. Scan the file using the application

3. **Expected Results:**
   - Status: **Clean File** (green) or **Suspicious** (yellow)
   - Should NOT be marked as malware
   - Confidence should be reasonable (not 0%)

**✓ PASS if:** File is not marked as malware
**✗ FAIL if:** File is falsely flagged as malicious

---

### ✅ Step 3: Verify Cloud Scanning Settings

**Test:** Cloud scanning can be enabled/disabled with API key configuration.

1. Navigate to **Settings** (⚙️)

2. Scroll to **Cloud Reputation Scanning** section

3. **Verify UI Elements:**
   - ✓ Privacy notice is displayed: "🔒 Privacy-Safe: Only file hashes are sent..."
   - ✓ Toggle switch: "☁️ Enable Cloud Reputation Scanning (Optional)"
   - ✓ API Key input field (masked with asterisks)
   - ✓ "Save Key" button
   - ✓ Rate limit notice: "Free API allows 4 requests/minute..."

4. **Test Toggle:**
   - Toggle cloud scanning ON
   - Check console output: Should see `[*] Cloud scanning enabled`
   - Toggle cloud scanning OFF
   - Check console output: Should see `[*] Cloud scanning disabled`

**✓ PASS if:** All UI elements are present and toggle works
**✗ FAIL if:** Missing elements or toggle doesn't work

---

### ✅ Step 4: Verify API Key Storage

**Test:** API key can be saved and persisted.

1. In Settings, enter a test API key: `test_api_key_12345`

2. Click **Save Key**

3. **Expected:**
   - Console shows: `[+] API key saved successfully`
   - Input field shows: `API Key saved ✓` (temporarily)

4. Close and reopen the application

5. Navigate to Settings

6. **Expected:**
   - API key field should show asterisks (key is loaded)

**✓ PASS if:** API key is saved and loaded on restart
**✗ FAIL if:** API key is not persisted

---

### ✅ Step 5: Verify Cloud Analysis Display (With Real API Key)

**Test:** Cloud analysis results are displayed when enabled.

**Prerequisites:** You need a real VirusTotal API key for this test.

1. Get a free API key from https://www.virustotal.com/gui/join-us

2. In Settings:
   - Enter your real VirusTotal API key
   - Click Save Key
   - Enable cloud scanning toggle

3. Scan a file that is NOT EICAR (e.g., a legitimate Windows executable like `C:\Windows\System32\notepad.exe`)

4. **Expected Results:**
   - Scan completes normally
   - If ML confidence is ambiguous (70-90%), you should see:
     ```
     ☁️ Cloud Analysis
     X / Y engines flagged this file
     Verdict: Clean | Suspicious | Malicious
     ```
   - If ML confidence is high (>90%), cloud analysis may not appear (not needed)

**✓ PASS if:** Cloud analysis appears for ambiguous files
**✗ FAIL if:** Cloud analysis never appears or causes errors

---

### ✅ Step 6: Verify Error Handling (No API Key)

**Test:** Application handles missing API key gracefully.

1. In Settings:
   - Clear the API key field (delete all text)
   - Click Save Key
   - Enable cloud scanning toggle

2. Scan any file

3. **Expected:**
   - Scan completes successfully
   - No crashes or errors
   - Console may show: `Error: No API key configured`
   - Detection continues using local methods only

**✓ PASS if:** Scan works without API key, no crashes
**✗ FAIL if:** Application crashes or scan fails

---

### ✅ Step 7: Verify Privacy Guarantees

**Test:** Only file hashes are sent, never file content.

**Method 1: Code Review**
1. Open `src/cloud_reputation.py`
2. Find the `query_cloud_reputation` method (line ~120)
3. Verify:
   - API URL uses `{hash}` placeholder: `files/{hash}`
   - No file upload code exists (no `files=` parameter in requests)
   - Only hash is used in API call

**Method 2: Network Monitoring (Advanced)**
1. Install Wireshark or Fiddler
2. Enable cloud scanning with real API key
3. Scan a file
4. Monitor network traffic to `virustotal.com`
5. Verify:
   - Only HTTPS GET request to `/api/v3/files/{hash}`
   - No POST requests with file data
   - Only hash appears in URL

**✓ PASS if:** Code review confirms hash-only submission
**✗ FAIL if:** File upload code is found

---

### ✅ Step 8: Verify Detection Priority Order

**Test:** Signatures take priority over ML and cloud.

1. **Test with EICAR (Signature):**
   - Scan EICAR file
   - Should be detected immediately with 100% confidence
   - Cloud analysis should NOT override this

2. **Test with Unknown File (ML + Cloud):**
   - Scan a file not in signature database
   - ML provides initial classification
   - Cloud is queried only if ML is ambiguous

**✓ PASS if:** EICAR is always 100% detected, cloud doesn't override
**✗ FAIL if:** Cloud results override signature detection

---

### ✅ Step 9: Verify Rate Limiting

**Test:** Application handles rate limits gracefully.

**Note:** This test requires a real API key and multiple scans.

1. Enable cloud scanning with real API key

2. Quickly scan 5-6 different files in succession

3. **Expected:**
   - First 4 scans work normally
   - 5th scan may show: `Error: Rate limit exceeded (4 requests/minute)`
   - Scan continues using local detection only
   - No crashes

4. Wait 1 minute and scan again

5. **Expected:**
   - Cloud scanning works again

**✓ PASS if:** Rate limit error is handled gracefully
**✗ FAIL if:** Application crashes on rate limit

---

### ✅ Step 10: Verify Result Caching

**Test:** Cloud results are cached to minimize API calls.

1. Enable cloud scanning with real API key

2. Scan a file (e.g., `notepad.exe`)

3. **First scan:**
   - Console shows: `[*] Querying VirusTotal for hash: ...`
   - Cloud analysis appears

4. Scan the SAME file again immediately

5. **Second scan:**
   - Console shows: `[*] Using cached cloud result for hash: ...`
   - Cloud analysis appears instantly (no API call)

**✓ PASS if:** Second scan uses cached result
**✗ FAIL if:** Every scan makes a new API call

---

## Summary

| Test | Description | Status |
|------|-------------|--------|
| 1 | EICAR Detection (100%) | ⬜ |
| 2 | Benign File Handling | ⬜ |
| 3 | Cloud Settings UI | ⬜ |
| 4 | API Key Storage | ⬜ |
| 5 | Cloud Analysis Display | ⬜ |
| 6 | Error Handling | ⬜ |
| 7 | Privacy Guarantees | ⬜ |
| 8 | Detection Priority | ⬜ |
| 9 | Rate Limiting | ⬜ |
| 10 | Result Caching | ⬜ |

**Mark each test:** ✓ (Pass) or ✗ (Fail)

---

## Troubleshooting

### Issue: Cloud analysis never appears
**Solution:** 
- Verify API key is correct
- Enable cloud scanning in Settings
- Scan files with ambiguous ML confidence (not EICAR)
- Check console for error messages

### Issue: "Rate limit exceeded" appears immediately
**Solution:**
- Wait 1 minute before scanning again
- Free API allows only 4 requests/minute
- Results are cached for 24 hours

### Issue: Application crashes when cloud scanning is enabled
**Solution:**
- Check internet connection
- Verify API key is valid
- Check console for error messages
- Disable cloud scanning and report the error

---

## Acceptance Criteria

**All tests must pass for successful integration:**

- ✅ EICAR is always detected (100% confidence)
- ✅ Benign files are not falsely flagged
- ✅ Cloud scanning can be enabled/disabled
- ✅ API key is stored securely
- ✅ Cloud analysis is displayed correctly
- ✅ Errors are handled gracefully
- ✅ Privacy is maintained (hash-only)
- ✅ Detection priority is respected
- ✅ Rate limits are handled
- ✅ Results are cached

**If any test fails, please report the specific failure for debugging.**
