# Import necessary libraries
import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

# Create a session with headers to mimic a web browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

# Function to get all forms from a given URL
def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

# Function to extract details of a form
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    # Loop through input tags in the form
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    # Populate details of the form
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

# Function to check if the response indicates a SQL injection vulnerability
def vulnerable(response):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the charachter string",
              "you have an error in you SQL syntax"
              }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Function to scan for SQL injection vulnerabilities
def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    # Loop through each form on the page
    for form in forms:
        details = form_details(form)

        # Loop through double and single quote characters
        for i in "\"'":
            data = {}
            # Loop through input tags in the form to create payload
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            # Print the URL and form details
            print(url)
            form_details(form)

            # Make a request based on the form method (POST or GET)
            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)

            # Check for SQL injection vulnerability in the response
            if vulnerable(res):
                print("SQL injection attack vulnerability in link:", url)
            else:
                print("No SQL injection attack vulnerability detected")
                break

if __name__ == "__main__":
    # Specify the URL to be checked for SQL injection vulnerability
    urlToBeChecked = "Enter Website to scan here"
    sql_injection_scan(urlToBeChecked)
