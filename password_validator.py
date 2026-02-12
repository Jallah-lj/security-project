class PasswordValidator:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()

    def _load_common_passwords(self):
        # Load common passwords from a file
        with open('common_passwords.txt', 'r') as f:
            return set(f.read().splitlines())

    def validate(self, password):
        # Validate the password against common passwords and perform strength checks
        if password in self.common_passwords:
            return False
        return self.check_pwned(password)

    def check_pwned(self, password):
        # Check if the password has been involved in a data breach
        import requests
        SHA1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = SHA1[:5], SHA1[5:]
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if response.status_code != 200:
            raise RuntimeError('Error fetching from API')
        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return False  # Password is pwned
        return True  # Password is safe

    def get_strength_label(self, password):
        # Determine the strength label of the password
        if not password:
            return 'Empty'
        elif len(password) < 6:
            return 'Weak'
        elif len(password) < 12:
            return 'Moderate'
        else:
            return 'Strong'

if __name__ == '__main__':
    password = input('Enter your password: ')
    validator = PasswordValidator()
    if validator.validate(password):
        print('Password is valid and not pwned.')
    else:
        print('Password is common or has been pwned.')