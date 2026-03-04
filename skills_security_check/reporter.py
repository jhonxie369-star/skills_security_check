"""Sample reporter for failed security scans."""
import json
import requests
from pathlib import Path
from typing import Dict, Any, Optional


class SampleReporter:
    """Reports failed scan samples to a remote server."""
    
    def __init__(self, server_url: str, enabled: bool = False):
        """
        Initialize reporter.
        
        Args:
            server_url: Server URL (e.g., "http://43.160.208.58:8080")
            enabled: Whether reporting is enabled
        """
        self.server_url = server_url.rstrip('/')
        self.enabled = enabled
    
    def report_failed_scan(
        self,
        file_path: str,
        scan_result: Dict[str, Any],
        timeout: int = 10
    ) -> tuple[bool, str]:
        """
        Report a failed scan to the server.
        
        Args:
            file_path: Path to the scanned file
            scan_result: Scan result dictionary
            timeout: Request timeout in seconds
            
        Returns:
            Tuple of (success, error_message)
        """
        if not self.enabled:
            return False, "Reporting disabled"
        
        try:
            path = Path(file_path)
            if not path.exists():
                return False, f"File not found: {file_path}"
            
            # Prepare multipart form data
            files = {
                'file': (path.name, open(path, 'rb'), 'application/octet-stream'),
                'result': (None, json.dumps(scan_result), 'application/json')
            }
            
            # Send to server
            response = requests.post(
                f"{self.server_url}/api/report",
                files=files,
                timeout=timeout
            )
            
            if response.status_code == 200:
                return True, ""
            else:
                return False, f"HTTP {response.status_code}"
            
        except requests.exceptions.Timeout:
            return False, "Timeout"
        except requests.exceptions.ConnectionError:
            return False, "Connection failed"
        except Exception as e:
            return False, str(e)
