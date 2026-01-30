"""Automated remediation engine for common vulnerabilities."""

import subprocess
import urllib.request
from typing import Dict, Any, Optional, List
from .definitions import ToolResult
from .validators import validate_ip


class RemediationEngine:
    """Handles automated fixes for common security vulnerabilities."""
    
    def __init__(self):
        self.remediation_db = {
            # Critical vulnerabilities
            "telnet_exposed": {
                "severity": "critical",
                "description": "Telnet service is exposed (unencrypted)",
                "fix_type": "disable_service",
                "commands": {
                    "linux": ["systemctl stop telnet", "systemctl disable telnet"],
                    "router_http": "curl -X POST http://{ip}/admin/services -d 'telnet=disabled'",
                    "router_ssh": "ssh admin@{ip} 'service telnet stop; chkconfig telnet off'"
                },
                "verification": "nmap -p 23 {ip} | grep -q closed"
            },
            
            "smb_v1_enabled": {
                "severity": "critical", 
                "description": "SMBv1 protocol enabled (ransomware risk)",
                "fix_type": "disable_protocol",
                "commands": {
                    "windows": ["powershell Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"],
                    "linux": ["echo 'min protocol = SMB2' >> /etc/samba/smb.conf", "systemctl restart smbd"]
                },
                "verification": "smbclient -L {ip} -m SMB1 2>&1 | grep -q 'protocol negotiation failed'"
            },
            
            # High severity
            "weak_ssl": {
                "severity": "high",
                "description": "Weak SSL/TLS configuration detected",
                "fix_type": "update_config",
                "commands": {
                    "router_http": "curl -X POST http://{ip}/admin/ssl -d 'min_version=TLSv1.2&ciphers=strong'",
                    "nginx": ["sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/' /etc/nginx/nginx.conf", "nginx -s reload"],
                    "apache": ["echo 'SSLProtocol TLSv1.2 +TLSv1.3' >> /etc/apache2/mods-enabled/ssl.conf", "systemctl reload apache2"]
                },
                "verification": "nmap --script ssl-enum-ciphers -p 443 {ip} | grep -q 'TLSv1.2\\|TLSv1.3'"
            },
            
            "upnp_enabled": {
                "severity": "medium",
                "description": "UPnP is enabled (port forwarding risk)",
                "fix_type": "disable_service",
                "commands": {
                    "router_http": "curl -X POST http://{ip}/admin/upnp -d 'enabled=false'",
                    "router_ssh": "ssh admin@{ip} 'upnpd stop; echo \"upnp_enable=0\" >> /etc/config'"
                },
                "verification": "nmap -sU -p 1900 {ip} | grep -q closed"
            },
            
            "default_credentials": {
                "severity": "high",
                "description": "Default credentials detected",
                "fix_type": "manual_guide",
                "commands": {
                    "guide": [
                        "1. Access device admin panel at http://{ip}",
                        "2. Login with current credentials",
                        "3. Navigate to System/Security settings",
                        "4. Change admin password to strong password (12+ chars)",
                        "5. Save configuration and reboot device"
                    ]
                },
                "verification": "manual"
            },
            
            "http_admin": {
                "severity": "medium",
                "description": "Admin interface accessible over HTTP",
                "fix_type": "redirect_https",
                "commands": {
                    "router_http": "curl -X POST http://{ip}/admin/security -d 'https_only=true&redirect_http=true'"
                },
                "verification": "curl -I http://{ip} | grep -q '301\\|302'"
            }
        }
    
    def identify_vulnerabilities(self, device_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify vulnerabilities that can be automatically fixed."""
        vulnerabilities = []
        ip = device_data.get("ip", "")
        open_ports = [p.get("port") for p in device_data.get("open_ports", [])]
        
        # Check for Telnet
        if 23 in open_ports:
            vulnerabilities.append({
                "vuln_id": "telnet_exposed",
                "ip": ip,
                "port": 23,
                **self.remediation_db["telnet_exposed"]
            })
        
        # Check for SMB
        if 445 in open_ports:
            vulnerabilities.append({
                "vuln_id": "smb_v1_enabled", 
                "ip": ip,
                "port": 445,
                **self.remediation_db["smb_v1_enabled"]
            })
        
        # Check encryption findings
        enc_check = device_data.get("encryption_check", {})
        if enc_check.get("risk_level") == "high":
            vulnerabilities.append({
                "vuln_id": "weak_ssl",
                "ip": ip,
                "port": 443,
                **self.remediation_db["weak_ssl"]
            })
        
        # Check UPnP
        upnp_check = device_data.get("upnp_check", {})
        if upnp_check.get("upnp_enabled"):
            vulnerabilities.append({
                "vuln_id": "upnp_enabled",
                "ip": ip,
                "port": 1900,
                **self.remediation_db["upnp_enabled"]
            })
        
        # Check for HTTP admin (router with port 80)
        device_type = device_data.get("device_type", "")
        if "router" in device_type.lower() and 80 in open_ports:
            vulnerabilities.append({
                "vuln_id": "http_admin",
                "ip": ip,
                "port": 80,
                **self.remediation_db["http_admin"]
            })
        
        return vulnerabilities
    
    def generate_fix_plan(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a fix plan for a vulnerability."""
        vuln_id = vulnerability["vuln_id"]
        ip = vulnerability["ip"]
        device_type = vulnerability.get("device_type", "unknown")
        
        # Select appropriate command based on device type
        commands = vulnerability["commands"]
        
        if "router" in device_type.lower():
            if "router_http" in commands:
                selected_cmd = commands["router_http"].format(ip=ip)
                method = "http_api"
            elif "router_ssh" in commands:
                selected_cmd = commands["router_ssh"].format(ip=ip)
                method = "ssh"
            else:
                selected_cmd = commands.get("guide", ["Manual fix required"])
                method = "manual"
        else:
            # Default to Linux commands
            selected_cmd = commands.get("linux", commands.get("guide", ["Manual fix required"]))
            method = "command"
        
        return {
            "vuln_id": vuln_id,
            "ip": ip,
            "severity": vulnerability["severity"],
            "description": vulnerability["description"],
            "fix_type": vulnerability["fix_type"],
            "method": method,
            "commands": selected_cmd if isinstance(selected_cmd, list) else [selected_cmd],
            "verification": vulnerability["verification"].format(ip=ip) if "{ip}" in vulnerability["verification"] else vulnerability["verification"],
            "estimated_time": "30 seconds",
            "risk_level": "low",  # Risk of applying the fix
            "reversible": method in ["http_api", "command"]
        }


def auto_fix_vulnerability(ip: str, vuln_id: str, device_data: Dict[str, Any]) -> ToolResult:
    """Automatically fix a specific vulnerability."""
    valid, error = validate_ip(ip)
    if not valid:
        return ToolResult(success=False, error=f"Invalid IP: {error}")
    
    engine = RemediationEngine()
    
    # Find the vulnerability
    vulnerabilities = engine.identify_vulnerabilities(device_data)
    target_vuln = next((v for v in vulnerabilities if v["vuln_id"] == vuln_id), None)
    
    if not target_vuln:
        return ToolResult(success=False, error=f"Vulnerability {vuln_id} not found or not fixable")
    
    # Generate fix plan
    fix_plan = engine.generate_fix_plan(target_vuln)
    
    return ToolResult(success=True, data={
        "fix_plan": fix_plan,
        "requires_approval": True,
        "safety_note": "This will modify device configuration. Ensure you have backup access."
    })


def execute_remediation(fix_plan: Dict[str, Any], dry_run: bool = True) -> ToolResult:
    """Execute a remediation plan."""
    if dry_run:
        return ToolResult(success=True, data={
            "status": "dry_run",
            "would_execute": fix_plan["commands"],
            "method": fix_plan["method"]
        })
    
    method = fix_plan["method"]
    commands = fix_plan["commands"]
    results = []
    
    try:
        if method == "http_api":
            # Execute HTTP API calls
            for cmd in commands:
                if cmd.startswith("curl"):
                    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
                    results.append({
                        "command": cmd,
                        "success": result.returncode == 0,
                        "output": result.stdout,
                        "error": result.stderr
                    })
        
        elif method == "ssh":
            # SSH commands (would need paramiko or similar)
            results.append({
                "command": "ssh_execution",
                "success": False,
                "error": "SSH execution not implemented - use manual method"
            })
        
        elif method == "command":
            # Local commands (for devices we have shell access to)
            for cmd in commands:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                results.append({
                    "command": cmd,
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr
                })
        
        elif method == "manual":
            # Return manual instructions
            return ToolResult(success=True, data={
                "status": "manual_required",
                "instructions": commands,
                "note": "Follow these steps manually"
            })
        
        # Check if all commands succeeded
        all_success = all(r["success"] for r in results)
        
        return ToolResult(success=all_success, data={
            "status": "completed" if all_success else "partial_failure",
            "results": results,
            "next_step": "verify_fix" if all_success else "check_errors"
        })
    
    except subprocess.TimeoutExpired:
        return ToolResult(success=False, error="Command execution timed out")
    except Exception as e:
        return ToolResult(success=False, error=f"Execution failed: {str(e)}")


def verify_fix(fix_plan: Dict[str, Any]) -> ToolResult:
    """Verify that a fix was applied successfully."""
    verification = fix_plan.get("verification", "")
    
    if verification == "manual":
        return ToolResult(success=True, data={
            "status": "manual_verification_required",
            "message": "Please verify the fix was applied correctly"
        })
    
    try:
        # Execute verification command
        result = subprocess.run(verification, shell=True, capture_output=True, text=True, timeout=10)
        
        return ToolResult(success=True, data={
            "verified": result.returncode == 0,
            "verification_output": result.stdout,
            "command": verification
        })
    
    except Exception as e:
        return ToolResult(success=False, error=f"Verification failed: {str(e)}")


def list_fixable_vulnerabilities(device_data: Dict[str, Any]) -> ToolResult:
    """List all vulnerabilities that can be automatically fixed."""
    engine = RemediationEngine()
    vulnerabilities = engine.identify_vulnerabilities(device_data)
    
    # Generate fix plans for all
    fix_plans = []
    for vuln in vulnerabilities:
        plan = engine.generate_fix_plan(vuln)
        fix_plans.append(plan)
    
    return ToolResult(success=True, data={
        "vulnerabilities": vulnerabilities,
        "fix_plans": fix_plans,
        "total_count": len(fix_plans),
        "by_severity": {
            "critical": len([p for p in fix_plans if p["severity"] == "critical"]),
            "high": len([p for p in fix_plans if p["severity"] == "high"]),
            "medium": len([p for p in fix_plans if p["severity"] == "medium"])
        }
    })
