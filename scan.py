import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import logging
import datetime
from concurrent.futures import ThreadPoolExecutor

# Create a timestamp for the log file
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# Configure logging with the timestamp in the filename
logging.basicConfig(filename=f'scan_log_{timestamp}.txt', level=logging.INFO)

# Create a separate file for storing vulnerable data
vulnerable_data_file = open(f'vulnerable_data_{timestamp}.txt', 'w')

def get_forms_from_url(url, session):
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        logging.error(f"Error retrieving forms from {url}: {e}")
        return []

def form_details(form):
    """
    Extract details of a form, including action, method, and input fields.

    Parameters:
        form (bs4.element.Tag): The BeautifulSoup Tag representing the HTML form.

    Returns:
        dict: Details of the form.
    """
    details_of_form = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form

def vulnerable(response, url, payload):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the character string",
              "you have an error in your SQL syntax"
             }
    for error in errors:
        if error in response.content.decode().lower():
            logging.warning(f"Vulnerability detected: {error}")

            # Log the vulnerability details to a separate file
            vulnerable_data_file.write(f"Vulnerability detected: {error}\n")
            vulnerable_data_file.write(f"URL: {url}\n")
            vulnerable_data_file.write(f"Payload: {payload}\n\n")
            return True
    return False

def sql_injection_scan(url, session):
    forms = get_forms_from_url(url, session)

    if not forms:
        logging.info(f"No forms found on {url}. Exiting.")
        return

    logging.info(f"[+] Detected {len(forms)} forms on {url}.")

    # SQL injection payload variations for form testing
    payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "1' OR 1=1; --", "1\" OR 1=1; --"]

    for form in forms:
        details = form_details(form)

        # Loop through each payload for form testing
        for payload in payloads:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{payload}"

            logging.info(f"\nScanning {url}")
            logging.info(f"Testing form: {details['action']} (Method: {details['method']})")

            if details["method"] == "post":
                res = session.post(url, data=data)
            elif details["method"] == "get":
                res = session.get(url, params=data)

            if vulnerable(res, url, payload):
                vulnerability_details = {
                    "type": "SQL Injection",
                    "form_action": details["action"],
                    "payload": payload
                }
                logging.warning(f"SQL injection attack vulnerability found with payload '{payload}'")
                return vulnerability_details

        # SQL injection payload variations for URL parameter testing
        url_params = parse_qs(urlparse(url).query)

        for param, values in url_params.items():
            for value in values:
                for payload in payloads:
                    modified_url = url.replace(f"{param}={value}", f"{param}={value}{payload}")
                    res = session.get(modified_url)

                    if vulnerable(res, modified_url, payload):
                        logging.warning(f"SQL injection attack vulnerability found with payload '{payload}' in URL: {modified_url}")
                    else:
                        logging.info(f"No SQL injection attack vulnerability detected with payload '{payload}' in URL: {modified_url}")
    return None  # Return None if no vulnerability is found

def extract_links_from_page(url, session):
    """
    Extract all links from a given page.

    Parameters:
        url (str): The URL of the page.
        session (requests.Session): The session to use for making HTTP requests.

    Returns:
        list: A list of URLs found on the page.
    """
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        links = [urljoin(url, a['href']) for a in soup.find_all('a', href=True)]
        return links
    except requests.RequestException as e:
        print(f"Error extracting links from {url}: {e}")
        return []

def crawl_and_scan(start_url, session, depth=2, max_workers=5):
    scanned_urls = set()

    def recursive_crawl_and_scan(url, current_depth):
        if current_depth > depth or url in scanned_urls:
            return
        scanned_urls.add(url)

        logging.info(f"\nScanning {url}")
        sql_injection_scan(url, session)

        links = extract_links_from_page(url, session)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(recursive_crawl_and_scan, links, [current_depth + 1] * len(links))

    recursive_crawl_and_scan(start_url, 1)

# Close the vulnerable data file
vulnerable_data_file.close()

if __name__ == "__main__":
    # Specify the starting URL to be checked for SQL injection vulnerability
    startUrlToBeChecked = "ENTER URL HERE"

    # Create a session with headers to mimic a web browser
    with requests.Session() as session:
        session.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        crawl_and_scan(startUrlToBeChecked, session)
