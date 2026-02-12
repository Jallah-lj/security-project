#!/usr/bin/env python3
"""
Security Audit Tool
Interactive tool for conducting security audits
"""

import json
import os
from datetime import datetime
from typing import Dict, List


class SecurityAuditTool:
    def __init__(self):
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'categories': {}
        }
        self.checklist = self._load_checklist()
    
    def _load_checklist(self) -> Dict:
        """Load security audit checklist"""
        return {
            'Authentication & Authorization': [
                'Multi-factor authentication is enabled',
                'Password policies meet security standards (min 12 chars, complexity)',
                'Session timeouts are configured appropriately',
                'Failed login attempts are monitored and limited',
                'Least privilege principle is applied to user roles',
                'Service accounts use strong, unique credentials',
            ],
            'Data Protection': [
                'Sensitive data is encrypted at rest',
                'Data is encrypted in transit (TLS 1.2+)',
                'Encryption keys are properly managed',
                'Personal data handling complies with regulations (GDPR, CCPA)',
                'Data backup and recovery processes are tested',
                'Secure data deletion procedures are in place',
            ],
            'Application Security': [
                'Input validation is implemented on all user inputs',
                'Output encoding prevents XSS attacks',
                'SQL injection prevention measures are in place',
                'CSRF protection is enabled',
                'Security headers are configured (CSP, HSTS, X-Frame-Options)',
                'Dependencies are regularly updated and scanned for vulnerabilities',
                'Secrets are not hardcoded in source code',
                'Error messages do not leak sensitive information',
            ],
            'Infrastructure Security': [
                'Systems are regularly patched and updated',
                'Unnecessary services and ports are disabled',
                'Firewall rules follow least privilege principle',
                'Security monitoring and logging is enabled',
                'Anti-malware solutions are deployed and updated',
                'Network segmentation is implemented',
            ],
            'Access Control': [
                'Access reviews are conducted regularly',
                'Privileged access is monitored and logged',
                'Remote access requires VPN or equivalent security',
                'Physical access to systems is controlled',
                'Account deprovisioning process is effective',
            ],
            'Incident Response': [
                'Incident response plan is documented',
                'Security incident contacts are identified',
                'Incident response procedures are tested',
                'Security logs are retained appropriately',
                'Breach notification procedures are defined',
            ],
            'Code Security': [
                'Security code reviews are conducted',
                'Static Application Security Testing (SAST) is performed',
                'Dynamic Application Security Testing (DAST) is performed',
                'Security testing is part of CI/CD pipeline',
                'Third-party code is reviewed before integration',
            ],
            'Cloud Security': [
                'Cloud storage buckets are not publicly accessible',
                'Cloud IAM policies follow least privilege',
                'Cloud resources are encrypted',
                'Cloud security monitoring is enabled',
                'Cloud configuration follows security benchmarks',
            ],
        }
    
    def run_audit(self):
        """Run interactive security audit"""
        print("=" * 60)
        print("Security Audit Tool")
        print("=" * 60)
        print("\nThis tool will guide you through a security audit.")
        print("For each item, answer: Yes (y), No (n), or Not Applicable (na)\n")
        
        for category, items in self.checklist.items():
            print(f"\n{'='*60}")
            print(f"{category}")
            print(f"{'='*60}\n")
            
            self.audit_results['categories'][category] = {
                'items': [],
                'compliant': 0,
                'non_compliant': 0,
                'not_applicable': 0
            }
            
            for item in items:
                while True:
                    response = input(f"{item}\n  [y/n/na]: ").strip().lower()
                    
                    if response in ['y', 'yes']:
                        status = 'compliant'
                        self.audit_results['categories'][category]['compliant'] += 1
                        break
                    elif response in ['n', 'no']:
                        status = 'non_compliant'
                        self.audit_results['categories'][category]['non_compliant'] += 1
                        notes = input("  Notes (why non-compliant): ").strip()
                        break
                    elif response in ['na', 'n/a']:
                        status = 'not_applicable'
                        self.audit_results['categories'][category]['not_applicable'] += 1
                        notes = ""
                        break
                    else:
                        print("  Invalid input. Please enter y, n, or na.")
                
                self.audit_results['categories'][category]['items'].append({
                    'item': item,
                    'status': status,
                    'notes': notes if status == 'non_compliant' else ''
                })
                
                print()  # Empty line for readability
        
        self._generate_report()
    
    def _generate_report(self):
        """Generate audit report"""
        print("\n" + "=" * 60)
        print("Security Audit Report")
        print("=" * 60)
        print(f"Date: {self.audit_results['timestamp']}\n")
        
        total_compliant = 0
        total_non_compliant = 0
        total_applicable = 0
        
        for category, data in self.audit_results['categories'].items():
            compliant = data['compliant']
            non_compliant = data['non_compliant']
            applicable = compliant + non_compliant
            
            total_compliant += compliant
            total_non_compliant += non_compliant
            total_applicable += applicable
            
            if applicable > 0:
                compliance_rate = (compliant / applicable) * 100
            else:
                compliance_rate = 100
            
            print(f"\n{category}")
            print(f"  Compliant: {compliant}")
            print(f"  Non-Compliant: {non_compliant}")
            print(f"  Not Applicable: {data['not_applicable']}")
            print(f"  Compliance Rate: {compliance_rate:.1f}%")
            
            if non_compliant > 0:
                print(f"\n  Issues found:")
                for item in data['items']:
                    if item['status'] == 'non_compliant':
                        print(f"    • {item['item']}")
                        if item['notes']:
                            print(f"      Notes: {item['notes']}")
        
        if total_applicable > 0:
            overall_compliance = (total_compliant / total_applicable) * 100
        else:
            overall_compliance = 100
        
        print("\n" + "=" * 60)
        print(f"Overall Compliance Rate: {overall_compliance:.1f}%")
        print("=" * 60)
        
        # Save report
        self._save_report()
    
    def _save_report(self):
        """Save audit report to file"""
        filename = f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.audit_results, f, indent=2)
        
        print(f"\n✓ Audit report saved to: {filename}")


def main():
    audit_tool = SecurityAuditTool()
    audit_tool.run_audit()


if __name__ == "__main__":
    main()
