import requests
from bs4 import BeautifulSoup

def fetch_page(url):
    """Fetch the content of the webpage."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def parse_page(content):
    """Parse the webpage content and extract titles and links."""
    soup = BeautifulSoup(content, 'html.parser')
    results = []

    for a_tag in soup.find_all('a', href=True):
        title = a_tag.get_text().strip()
        link = a_tag['href']
        results.append((title, link))

    return results

def scrape_website(url):
    """Scrape the given website for titles and links."""
    print(f"Starting scrape for {url}")
    page_content = fetch_page(url)

    if not page_content:
        print(f"Failed to retrieve content from {url}")
        return

    parsed_data = parse_page(page_content)
    
    print(f"Scraping complete for {url}. Found {len(parsed_data)} links.")
    for title, link in parsed_data:
        print(f"Title: {title}, Link: {link}")

if __name__ == "__main__":
    # Example usage
    target_url = input("Please Enter URL of the Target Website: ")
    scrape_website(target_url)