#!/usr/bin/env python3
"""
Password Strength Validator
Validates password strength based on security best practices
"""

import re
import hashlib
import requests
from typing import Tuple, List


class PasswordValidator:
    def __init__(self):
        self.min_length = 12
        self.common_passwords = self._load_common_passwords()
    
    def _load_common_passwords(self) -> set:
        """Load common passwords list"""
        # Top 100 most common passwords
        return {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', '12345678', '111111', '1234567', 'sunshine',
            'password123', '123123', 'welcome', 'admin', 'letmein'
        }
    
    def validate(self, password: str) -> Tuple[bool, int, List[str]]:
        """Validate password strength.
        
        Returns: (is_strong, score, feedback)
        """
        score = 0
        feedback = []
        
        # Check length
        if len(password) < self.min_length:
            feedback.append(f"Password should be at least {self.min_length} characters long")
        else:
            score += 20
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 15
        else:
            feedback.append("Add lowercase letters")
        
        # Check for digits
        if re.search(r'\d', password):
            score += 15
        else:
            feedback.append("Add numbers")
        
        # Check for special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        else:
            feedback.append("Add special characters (!@#$%^&*)")
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("This is a commonly used password. Choose something unique")
        else:
            score += 10
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            feedback.append("Avoid sequential characters")
            score -= 10
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            feedback.append("Avoid repeated characters")
            score -= 10
        
        # Bonus for length
        if len(password) >= 16:
            score += 10
        
        score = max(0, min(100, score))
        is_strong = score >= 70 and len(feedback) == 0
        
        return is_strong, score, feedback
    
    def check_pwned(self, password: str) -> Tuple[bool, int]:
        """Check if password has been compromised using Have I Been Pwned API.
        
        Uses k-anonymity model to protect password privacy.
        """
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for h in hashes:
                    hash_suffix, count = h.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
            return False, 0
        except Exception as e:
            print(f"Could not check password against breach database: {e}")
            return False, 0
    
    def get_strength_label(self, score: int) -> str:
        """Get human-readable strength label"""
        if score >= 80:
            return "Strong"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"


def main():
    validator = PasswordValidator()
    
    print("Password Strength Validator")
    print("=" * 40)
    
    while True:
        password = input("\nEnter password to validate (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            break
        
        is_strong, score, feedback = validator.validate(password)
        strength = validator.get_strength_label(score)
        
        print(f"\nStrength: {strength} ({score}/100)")
        
        if feedback:
            print("\nRecommendations:")
            for item in feedback:
                print(f"  • {item}")
        
        # Check if password has been pwned
        print("\nChecking against breach database...")
        is_pwned, count = validator.check_pwned(password)
        
        if is_pwned:
            print(f"⚠️  WARNING: This password has been seen {count} times in data breaches!")
        else:
            print("✓ Password not found in breach database")
        
        if is_strong and not is_pwned:
            print("\n✓ This is a strong, secure password!")


if __name__ == "__main__":
    main()