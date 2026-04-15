<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

# ParamSpecter-Crawler

ParamSpecter is an advanced reconnaissance web crawler designed for bug bounty hunting and cybersecurity research. It performs deep crawling of web applications, extracts endpoints, analyzes JavaScript files, detects sensitive information, and generates structured outputs for further testing.

---

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Do not use ParamSpecter on systems without proper permission.

---

## Features

- Multi-threaded crawling engine
- Depth-based crawling
- Robots.txt support (optional)
- Internal and external link discovery
- Parameter detection (?id=, ?search=, etc.)
- JavaScript file extraction
- Deep JavaScript endpoint analysis
- Secret detection:
  - API keys
  - Tokens
  - Bearer authentication
  - AWS keys
- Email, IP, and subdomain extraction
- Technology fingerprinting
- WAF detection
- Security headers analysis
- JSON and CSV output

---

## How It Works

### 1. Initialization

ParamSpecter starts by taking a target URL and initializing:

- A queue-based crawling system
- Thread workers
- Depth and page limits
- HTTP session with headers

---

### 2. Crawling Engine

The crawler uses multiple threads. Each worker:

1. Fetches a URL from the queue
2. Checks if it was already visited
3. Verifies robots.txt rules (if enabled)
4. Sends an HTTP request
5. Parses the response

---

### 3. Page Analysis

Each page is processed using:

analyze_page(url, resp, soup, raw_html)

This function extracts:

#### Basic Information
- Status code
- Content type
- Server headers
- Redirect chain

#### Metadata
- Page title
- Meta description

#### Links
- Internal links
- External links
- Social media links

---

### 4. JavaScript Analysis

ParamSpecter extracts JavaScript files from HTML:

<script src="...">

Then downloads and scans them for:

- Hidden API endpoints
- Internal routes

Examples:
- /api/login
- /api/v1/user
- /admin/dashboard
- /auth/token

---

### 5. Secret Detection

The crawler scans JavaScript content for sensitive data using regex patterns.

It detects:

- API keys
- Tokens
- Bearer authentication tokens
- AWS access keys

Example findings:

api_key=abcd1234  
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...  
AKIAIOSFODNN7EXAMPLE  

---

### 6. Data Collection

ParamSpecter collects:

- URLs
- Parameters
- Emails
- Phone numbers
- IP addresses
- Subdomains
- Technologies
- WAF detection
- Security headers

---

### 7. Output

Results are saved in:

- JSON format
- CSV format

Example file:

paramspecter_example_com_20260101.json

---

## Installation

Clone the repository:

git clone https://github.com/yourusername/ParamSpecter.git  
cd ParamSpecter  

Install dependencies:

pip install -r requirements.txt  

---

## Requirements

Create a requirements.txt file:

requests  
beautifulsoup4  

---

## Usage

Basic command:

python ParamSpecter.py https://example.com  

---

## Options

-m, --max-pages     Maximum pages to crawl (default: 50)  
-d, --delay         Delay between requests (default: 0.8)  
-D, --depth         Crawl depth (default: 3)  
-t, --threads       Number of threads (default: 5)  
--timeout           Request timeout (default: 10)  
-o, --output        Output format (json, csv, both)  
--follow-external   Crawl external links  
--ignore-robots     Ignore robots.txt rules  
-u, --user-agent    Custom user agent  

---

## Example

python ParamSpecter.py https://testphp.vulnweb.com -D 2 -t 5  

---

## Project Structure

ParamSpecter.py      Main crawler script  
requirements.txt     Dependencies  
README.md            Documentation  

---

## Use Cases

- Bug bounty reconnaissance
- Endpoint discovery
- Parameter identification
- JavaScript analysis
- Sensitive data exposure detection
- Web application mapping

---

## Limitations

- Does not execute JavaScript (no browser engine)
- May miss dynamic content
- Basic regex-based detection (can include false positives)

---

## Future Improvements

- Headless browser support (Playwright)
- Advanced parameter fuzzing
- Secret validation
- Subdomain enumeration
- Integration with tools like ffuf and nuclei

---

## Author

Developed by Boltx

---

## License

This project is for educational use only.
