import requests

def brute_force_directories(url, wordlist):
    # Read wordlist file
    with open(wordlist, 'r') as f:
        directories = f.read().splitlines()

    # Iterate over each directory and check its existence
    for directory in directories:
        target_url = f"{url}/{directory}"
        response = requests.get(target_url)
        
        if response.status_code == 200:
            print(f"Found directory: {target_url}")
        elif response.status_code == 403:
            print(f"Access forbidden: {target_url}")
        elif response.status_code == 404:
            print(f"Not found: {target_url}")

if __name__ == "__main__":
    # Example usage:
    url = input("Please Enter the URL of the Target Website: ")
    wordlist = 'common.txt'  # Replace with your wordlist file

    brute_force_directories(url, wordlist)