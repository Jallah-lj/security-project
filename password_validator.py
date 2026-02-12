    def check_pwned(self, password: str) -> Tuple[bool, int]:
        """Check if password has been compromised using Have I Been Pwned API
        Uses k-anonymity model
        """
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
