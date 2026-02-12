#!/usr/bin/env python3
"""
Security Scanner Tool
Automated scanner for common security vulnerabilities
"""

import os
import re
import hashlib
from pathlib import Path
from typing import List, Dict
from fnmatch import fnmatch
from colorama import init, Fore, Style

init(autoreset=True)


class SecurityScanner:
    def __init__(self, directory: str = "."):
        self.directory = directory
        self.vulnerabilities = []
        # Directories to exclude from scanning
        self.exclude_dirs = {
            'venv', 'env', '.venv', '.env',
            'node_modules', '.git', '__pycache__',
            '.pytest_cache', '.tox', 'build', 'dist',
            '*.egg-info', '.mypy_cache'
        }
    
    def _should_exclude_dir(self, dirname: str) -> bool:
        """Check if a directory should be excluded from scanning"""
        # First check for exact match (faster)
        if dirname in self.exclude_dirs:
            return True
        # Then check for pattern match (slower but handles wildcards)
        for pattern in self.exclude_dirs:
            if fnmatch(dirname, pattern):
                return True
        return False
        
    def scan(self) -> List[Dict]:
        """Run all security scans"""
        print(f"{Fore.CYAN}Starting security scan...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Excluding directories: {', '.join(sorted(self.exclude_dirs))}{Style.RESET_ALL}\n")
        
        self.check_hardcoded_secrets()
        self.check_insecure_functions()
        self.check_file_permissions()
        self.check_dependency_vulnerabilities()
        
        return self.vulnerabilities
    
    def check_hardcoded_secrets(self):
        """Scan for hardcoded secrets and credentials"""
        print(f"{Fore.YELLOW}[1/4] Checking for hardcoded secrets...{Style.RESET_ALL}")
        
        patterns = {
            'API Key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Password': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Secret': r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Token': r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
        }
        
        for root, dirs, files in os.walk(self.directory):
            # Remove excluded directories from the search
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d)]
            
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php', '.env')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for secret_type, pattern in patterns.items():
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    self.vulnerabilities.append({
                                        'type': 'Hardcoded Secret',
                                        'severity': 'HIGH',
                                        'file': filepath,
                                        'description': f'Possible {secret_type} found',
                                        'line': content[:match.start()].count('\n') + 1
                                    })
                    except Exception as e:
                        pass
    
    def check_insecure_functions(self):
        """Check for usage of insecure functions"""
        print(f"{Fore.YELLOW}[2/4] Checking for insecure functions...{Style.RESET_ALL}")
        
        insecure_patterns = {
            'eval()': r'\beval\s*\(',
            'exec()': r'\bexec\s*\(',
            'pickle.loads()': r'pickle\.loads\s*\(',
            'os.system()': r'os\.system\s*\(',
            'subprocess without shell=False': r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
        }
        
        for root, dirs, files in os.walk(self.directory):
            # Remove excluded directories from the search
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d)]
            
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for func_name, pattern in insecure_patterns.items():
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    self.vulnerabilities.append({
                                        'type': 'Insecure Function',
                                        'severity': 'MEDIUM',
                                        'file': filepath,
                                        'description': f'Insecure function {func_name} detected',
                                        'line': content[:match.start()].count('\n') + 1
                                    })
                    except Exception as e:
                        pass
    
    def check_file_permissions(self):
        """Check for overly permissive file permissions"""
        print(f"{Fore.YELLOW}[3/4] Checking file permissions...{Style.RESET_ALL}")
        
        for root, dirs, files in os.walk(self.directory):
            # Remove excluded directories from the search
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d)]
            
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    mode = os.stat(filepath).st_mode
                    if mode & 0o002:  # World writable
                        self.vulnerabilities.append({
                            'type': 'File Permission',
                            'severity': 'HIGH',
                            'file': filepath,
                            'description': 'File is world-writable',
                            'line': 'N/A'
                        })
                except Exception as e:
                    pass
    
    def check_dependency_vulnerabilities(self):
        """Check for known vulnerable dependencies"""
        print(f"{Fore.YELLOW}[4/4] Checking dependencies...{Style.RESET_ALL}")
        
        requirements_file = os.path.join(self.directory, 'requirements.txt')
        if os.path.exists(requirements_file):
            print(f"{Fore.GREEN}Found requirements.txt. Consider running 'pip-audit' for vulnerability scanning.{Style.RESET_ALL}")
    
    def print_report(self):
        """Print security scan report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Security Scan Report{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}✓ No vulnerabilities found!{Style.RESET_ALL}\n")
            return
        
        # Group by severity
        high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v['severity'] == 'LOW']
        
        print(f"{Fore.RED}HIGH: {len(high)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}MEDIUM: {len(medium)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}LOW: {len(low)}{Style.RESET_ALL}\n")
        
        for vuln in self.vulnerabilities:
            color = Fore.RED if vuln['severity'] == 'HIGH' else Fore.YELLOW if vuln['severity'] == 'MEDIUM' else Fore.BLUE
            print(f"{color}[{vuln['severity']}] {vuln['type']}{Style.RESET_ALL}")
            print(f"  File: {vuln['file']}:{vuln['line']}")
            print(f"  Description: {vuln['description']}\n")


def main():
    scanner = SecurityScanner(".")
    scanner.scan()
    scanner.print_report()


if __name__ == "__main__":
    main()
