"""
Cloud-Based Reputation API Module
Privacy-Safe Implementation - Only SHA-256 hashes are submitted, never file content
"""

import requests
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path


class CloudReputationChecker:
    """
    VirusTotal-based cloud reputation checker.
    Privacy-first design: Only submits file hashes, never file content.
    """
    
    def __init__(self):
        self.config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config',
            'cloud_config.json'
        )
        self.cache_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'logs',
            'cloud_cache.json'
        )
        
        # Load configuration
        self.config = self.load_config()
        
        # VirusTotal API endpoint
        self.vt_api_url = "https://www.virustotal.com/api/v3/files/{hash}"
        
        # Load cache
        self.cache = self.load_cache()
        
        print(f"[*] Cloud Reputation Checker initialized (Enabled: {self.config.get('enabled', False)})")
    
    def load_config(self):
        """Load cloud scanning configuration"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                # Default config
                return {
                    "enabled": False,
                    "api_key": "",
                    "cache_duration_hours": 24,
                    "timeout_seconds": 5,
                    "max_retries": 2
                }
        except Exception as e:
            print(f"[!] Error loading cloud config: {e}")
            return {"enabled": False, "api_key": "", "cache_duration_hours": 24, "timeout_seconds": 5, "max_retries": 2}
    
    def save_config(self, config):
        """Save cloud scanning configuration"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            self.config = config
            return True
        except Exception as e:
            print(f"[!] Error saving cloud config: {e}")
            return False
    
    def load_cache(self):
        """Load cached cloud scan results"""
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"[!] Error loading cache: {e}")
            return {}
    
    def save_cache(self):
        """Save cache to disk"""
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving cache: {e}")
    
    def get_cached_result(self, file_hash):
        """
        Retrieve cached cloud scan result if available and not expired.
        
        Args:
            file_hash: SHA-256 hash of the file
            
        Returns:
            Cached result dict or None if not found/expired
        """
        if file_hash not in self.cache:
            return None
        
        cached = self.cache[file_hash]
        cache_time = datetime.fromisoformat(cached.get('timestamp', '2000-01-01T00:00:00'))
        cache_duration = timedelta(hours=self.config.get('cache_duration_hours', 24))
        
        if datetime.now() - cache_time > cache_duration:
            # Cache expired
            del self.cache[file_hash]
            self.save_cache()
            return None
        
        print(f"[*] Using cached cloud result for hash: {file_hash[:16]}...")
        return cached.get('result')
    
    def cache_result(self, file_hash, result):
        """
        Cache a cloud scan result.
        
        Args:
            file_hash: SHA-256 hash of the file
            result: Result dictionary to cache
        """
        self.cache[file_hash] = {
            'timestamp': datetime.now().isoformat(),
            'result': result
        }
        self.save_cache()
    
    def query_cloud_reputation(self, file_hash):
        """
        Query VirusTotal API for file reputation using SHA-256 hash.
        PRIVACY-SAFE: Only submits hash, never file content.
        
        Args:
            file_hash: SHA-256 hash of the file
            
        Returns:
            Dictionary with cloud analysis results or None on error
            {
                'engines_flagged': int,
                'total_engines': int,
                'verdict': 'Clean' | 'Suspicious' | 'Malicious',
                'scan_date': str,
                'error': str (if error occurred)
            }
        """
        # Check if cloud scanning is enabled
        if not self.config.get('enabled', False):
            return None
        
        # Check for API key
        api_key = self.config.get('api_key', '').strip()
        if not api_key:
            return {
                'error': 'No API key configured',
                'engines_flagged': 0,
                'total_engines': 0,
                'verdict': 'Unknown'
            }
        
        # Check cache first
        cached = self.get_cached_result(file_hash)
        if cached:
            return cached
        
        print(f"[*] Querying VirusTotal for hash: {file_hash[:16]}...")
        
        try:
            # Prepare request
            url = self.vt_api_url.format(hash=file_hash)
            headers = {
                'x-apikey': api_key,
                'Accept': 'application/json'
            }
            
            timeout = self.config.get('timeout_seconds', 5)
            
            print(f"[*] Sending request to VirusTotal (Timeout: {timeout}s)...")
            
            # Make API request (PRIVACY-SAFE: Only hash in URL, no file upload)
            response = requests.get(url, headers=headers, timeout=timeout)
            
            # Handle rate limiting
            if response.status_code == 429:
                return {
                    'error': 'Rate limit exceeded (4 requests/minute)',
                    'engines_flagged': 0,
                    'total_engines': 0,
                    'verdict': 'Unknown'
                }
            
            # Handle not found (file not in VT database)
            if response.status_code == 404:
                result = {
                    'engines_flagged': 0,
                    'total_engines': 0,
                    'verdict': 'Unknown',
                    'scan_date': 'Not in database'
                }
                self.cache_result(file_hash, result)
                return result
            
            # Handle other errors
            if response.status_code != 200:
                return {
                    'error': f'API error: HTTP {response.status_code}',
                    'engines_flagged': 0,
                    'total_engines': 0,
                    'verdict': 'Unknown'
                }
            
            # Parse response
            result = self.parse_cloud_response(response.json())
            
            # Cache successful result
            if result and 'error' not in result:
                self.cache_result(file_hash, result)
            
            return result
            
        except requests.exceptions.Timeout:
            return {
                'error': 'Request timeout',
                'engines_flagged': 0,
                'total_engines': 0,
                'verdict': 'Unknown'
            }
        except requests.exceptions.ConnectionError:
            return {
                'error': 'Network connection failed',
                'engines_flagged': 0,
                'total_engines': 0,
                'verdict': 'Unknown'
            }
        except Exception as e:
            print(f"[!] Cloud reputation query error: {e}")
            return {
                'error': str(e),
                'engines_flagged': 0,
                'total_engines': 0,
                'verdict': 'Unknown'
            }
    
    def parse_cloud_response(self, response_json):
        """
        Parse VirusTotal API response into standardized format.
        
        Args:
            response_json: JSON response from VirusTotal API
            
        Returns:
            Standardized result dictionary
        """
        try:
            data = response_json.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            # Count engines
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)
            
            engines_flagged = malicious + suspicious
            total_engines = malicious + suspicious + undetected + harmless
            
            # Determine verdict
            if total_engines == 0:
                verdict = 'Unknown'
            elif engines_flagged == 0:
                verdict = 'Clean'
            elif engines_flagged >= 5:  # 5+ engines flagged = Malicious
                verdict = 'Malicious'
            else:  # 1-4 engines flagged = Suspicious
                verdict = 'Suspicious'
            
            # Get scan date
            scan_date = attributes.get('last_analysis_date', 'Unknown')
            if isinstance(scan_date, int):
                scan_date = datetime.fromtimestamp(scan_date).strftime('%Y-%m-%d %H:%M')
            
            result = {
                'engines_flagged': engines_flagged,
                'total_engines': total_engines,
                'verdict': verdict,
                'scan_date': scan_date,
                'malicious_count': malicious,
                'suspicious_count': suspicious
            }
            
            print(f"[*] Cloud result: {engines_flagged}/{total_engines} engines flagged - Verdict: {verdict}")
            
            return result
            
        except Exception as e:
            print(f"[!] Error parsing cloud response: {e}")
            return {
                'error': 'Failed to parse response',
                'engines_flagged': 0,
                'total_engines': 0,
                'verdict': 'Unknown'
            }
    
    def is_enabled(self):
        """Check if cloud scanning is enabled"""
        return self.config.get('enabled', False)
    
    def set_enabled(self, enabled):
        """Enable or disable cloud scanning"""
        self.config['enabled'] = enabled
        self.save_config(self.config)
    
    def set_api_key(self, api_key):
        """Set VirusTotal API key"""
        self.config['api_key'] = api_key
        self.save_config(self.config)
    
    def get_api_key(self):
        """Get configured API key (for display purposes)"""
        return self.config.get('api_key', '')


# Test functionality
if __name__ == "__main__":
    checker = CloudReputationChecker()
    
    # Test with EICAR hash (known malware test file)
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    
    print("\n--- Testing Cloud Reputation Checker ---")
    print(f"Cloud scanning enabled: {checker.is_enabled()}")
    
    if checker.is_enabled() and checker.get_api_key():
        print(f"\nQuerying EICAR test file hash...")
        result = checker.query_cloud_reputation(eicar_hash)
        print(f"Result: {json.dumps(result, indent=2)}")
    else:
        print("\n[!] Cloud scanning disabled or no API key configured")
        print("To test: Enable cloud scanning and set API key in config/cloud_config.json")
