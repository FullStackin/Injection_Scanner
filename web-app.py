from flask import Flask, jsonify, render_template, request
import requests
import logging
import datetime
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from scan import get_forms_from_url, form_details, sql_injection_scan, extract_links_from_page, crawl_and_scan

app = Flask(__name__, static_url_path='/static')

# Configure logging
logging.basicConfig(filename=f'scan_log_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', level=logging.INFO)

# Create a separate file for storing vulnerable data
vulnerable_data_file = open(f'vulnerable_data_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', 'w')

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

def get_forms_from_url(url, session):
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        logging.error(f"Error retrieving forms from {url}: {e}")
        return []

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url_to_check = request.form["url"]

        # Create a session with headers to mimic a web browser
        with requests.Session() as session:
            session.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

            logging.basicConfig(filename=f'scan_log_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', level=logging.INFO)

            # Simulate the scan initiation
            # You can replace this with your actual scan logic
            # For simplicity, I'm just printing the URL here
            print(f"Initiating scan for URL: {url_to_check}")

            return jsonify({"status": "Scan initiated", "url": url_to_check})

    return render_template("index.html")

# Add the /start_scan route
@app.route("/start_scan", methods=["POST"])
def start_scan():
    # Get the JSON data from the request
    data = request.json

    # Simulate the scan initiation
    # You can replace this with your actual scan logic
    # For simplicity, I'm just printing the URL here
    print(f"Initiating scan for URL: {data['url']}")

    # Return a response in JSON format
    return jsonify({"status": "Scan initiated", "url": data["url"]})

@app.route("/results", methods=["GET"])
def results():
    # Get the scanned URL from the request parameters
    url_to_check = request.args.get('url', '')

    # Placeholder for vulnerabilities, replace with actual scan results
    vulnerabilities = scan_and_get_vulnerabilities(url_to_check)

    return jsonify({
        "url": url_to_check,
        "vulnerabilities": vulnerabilities
    })

def scan_and_get_vulnerabilities(url):
    # Perform your actual scan here and return the specific vulnerabilities found
    # You might need to modify your scan logic to return detailed information
    # For example, instead of just detecting SQL injection, return details about the specific vulnerability

    # Sample vulnerabilities for demonstration purposes
    vulnerabilities = []

    # Simulate detecting SQL injection vulnerability
    sql_injection_result = sql_injection_scan(url)
    if sql_injection_result:
        vulnerabilities.append({"type": "SQL Injection", "details": sql_injection_result})

    # Add more logic to detect other vulnerabilities and append them to the vulnerabilities list

    return vulnerabilities

if __name__ == "__main__":
    app.run(debug=True)
