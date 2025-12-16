# Cloud Reputation Scanning - User Guide

## Overview

SENTINEL AI now includes **optional cloud-based reputation scanning** powered by VirusTotal. This feature provides an additional layer of protection by querying a global threat intelligence database for files with ambiguous detection results.

## 🔐 Privacy Guarantees

**Your privacy is our priority:**

- ✅ **Only file hashes (SHA-256) are sent to the cloud**
- ✅ **File content is NEVER uploaded**
- ✅ **Cloud scanning is completely optional**
- ✅ **You control when it's enabled**
- ✅ **All cloud queries are logged for transparency**

## 🚀 Getting Started

### Step 1: Obtain a VirusTotal API Key

1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Navigate to your profile settings
4. Copy your API key

**Note:** The free tier allows 4 requests per minute, which is sufficient for most users.

### Step 2: Configure Cloud Scanning

1. Launch SENTINEL AI
2. Navigate to **Settings** (⚙️)
3. Scroll to the **Cloud Reputation Scanning** section
4. Paste your API key in the input field
5. Click **Save Key**
6. Toggle **☁️ Enable Cloud Reputation Scanning** to ON

## 🎯 How It Works

### Detection Priority Order

SENTINEL AI uses a **hybrid detection approach** with strict priority:

1. **Signature-based detection** (EICAR, known malware hashes)
   - If a file matches a known signature → **Immediate detection (100% confidence)**
   
2. **Local ML-based classification**
   - Advanced machine learning model analyzes file features
   - Provides confidence score and threat classification
   
3. **Cloud reputation API** (optional fallback)
   - **Only queried when:**
     - Cloud scanning is enabled
     - ML confidence is ambiguous (70-90% range)
     - File is not already confirmed by signatures
   - Queries VirusTotal with file hash
   - Displays results from multiple antivirus engines

### When Cloud Scanning is Triggered

Cloud scanning is **NOT** used for:
- Files with known malware signatures (already 100% detected)
- Files with high ML confidence (>90% benign or >95% malicious)
- Non-executable files (unless explicitly scanned)

Cloud scanning **IS** used for:
- Suspicious files with ambiguous ML confidence (70-90%)
- Unknown executables with no signature match
- Files requiring additional validation

## 📊 Understanding Cloud Results

When cloud scanning is active, you'll see:

```
☁️ Cloud Analysis
X / Y engines flagged this file
Verdict: Clean | Suspicious | Malicious
```

### Verdict Meanings

- **Clean** (0 engines flagged): No antivirus engines detected threats
- **Suspicious** (1-4 engines flagged): Some engines flagged the file
- **Malicious** (5+ engines flagged): Multiple engines detected threats

### How Cloud Results Influence Detection

- **Malicious verdict (5+ engines):** Upgrades suspicious files to malware
- **Suspicious verdict (1-4 engines):** Keeps file as suspicious, slight confidence boost
- **Clean verdict (0 engines):** May downgrade to benign if local confidence is low

**Important:** Cloud results **never override** signature-based detection!

## ⚠️ Rate Limiting

The free VirusTotal API has a limit of **4 requests per minute**.

**What happens when you hit the limit:**
- You'll see: `Error: Rate limit exceeded (4 requests/minute)`
- Detection continues using local methods only
- Results are cached for 24 hours to minimize API calls

**Tips to avoid rate limits:**
- Scan files individually rather than bulk scanning
- Use Quick Scan sparingly with cloud enabled
- Results are cached, so re-scanning the same file won't use API quota

## 🔧 Troubleshooting

### "No API key configured" Error

**Solution:** Enter your VirusTotal API key in Settings and click Save Key.

### "Request timeout" Error

**Cause:** Network connection issue or VirusTotal is slow to respond.

**Solution:** 
- Check your internet connection
- Try scanning again
- Detection will continue using local methods

### "API error: HTTP 401" Error

**Cause:** Invalid or expired API key.

**Solution:**
- Verify your API key is correct
- Generate a new key from VirusTotal
- Update the key in Settings

### Cloud Analysis Not Showing

**Possible causes:**
1. Cloud scanning is disabled in Settings
2. File was detected by signatures (100% confidence)
3. ML confidence is very high/low (not ambiguous)
4. API key is missing or invalid

## 🛡️ Security Best Practices

1. **Keep your API key private** - Don't share it with others
2. **Enable cloud scanning for unknown files** - Provides additional validation
3. **Trust signature detection first** - Known malware is always caught
4. **Review suspicious files manually** - Cloud analysis helps inform decisions
5. **Disable cloud scanning for sensitive files** - If privacy is a concern

## 📝 Technical Details

### What Data is Sent?

Only the **SHA-256 hash** of the file:
```
Example: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

This hash is a **one-way cryptographic fingerprint** - it's impossible to reconstruct the file from the hash.

### Caching

Cloud scan results are cached locally for **24 hours** to:
- Reduce API calls
- Improve scan speed
- Stay within rate limits

Cache location: `logs/cloud_cache.json`

### Configuration

Cloud settings are stored in: `config/cloud_config.json`

```json
{
  "enabled": false,
  "api_key": "your_api_key_here",
  "cache_duration_hours": 24,
  "timeout_seconds": 10,
  "max_retries": 2
}
```

## ❓ FAQ

**Q: Is cloud scanning required?**  
A: No, it's completely optional. Local detection works independently.

**Q: Will my files be uploaded to VirusTotal?**  
A: No, only the SHA-256 hash is sent. File content never leaves your computer.

**Q: Can I use a different cloud service?**  
A: Currently only VirusTotal is supported. Future versions may add more providers.

**Q: Does cloud scanning slow down scans?**  
A: Slightly (1-3 seconds), but only for ambiguous files. Cached results are instant.

**Q: What if I don't have an API key?**  
A: Cloud scanning will be disabled, but all local detection features work normally.

**Q: Is the free API key enough?**  
A: Yes, for individual file scanning. Bulk scanning may hit rate limits.

## 📞 Support

For issues or questions:
- Check the troubleshooting section above
- Review the implementation plan: `implementation_plan.md`
- Ensure you're using the latest version

---

**Remember:** Cloud scanning is an **optional enhancement** to SENTINEL AI's already robust local detection. Your privacy and security are always protected! 🛡️
