# vuln-erabilityAgeAnalyzer
Analyzes vulnerability reports and calculates the average and maximum age of reported vulnerabilities, providing insights into reporting lag and overall vulnerability management effectiveness. It fetches reports from an RSS feed or a JSON API endpoint, filters them by priority and keywords, and prints or saves a summary report.

Verified behavior: dates are normalized to UTC before ages are computed, future-dated entries are excluded and counted in the report, and entries whose date cannot be determined are skipped and named. Priority matching checks a report's own priority or severity field first when the feed provides one; otherwise the priority must appear as a whole word in the title or description, so a word that merely contains it does not count. RSS entries that carry their body in the summary field are read as well, and dates are accepted from the published, pubDate, updated, or date fields, from a parsed publication timestamp, or from a date regex applied to the original description text. A JSON API endpoint must return a list of reports, or an object wrapping that list under a results, vulnerabilities, entries, reports, or items key; any other shape is a fetch error and exits non-zero. When nothing matches, a report carrying an explicit no matches status is written and the run exits non-zero.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-erabilityageanalyzer`

Then install the dependencies listed in requirements.txt: python-dateutil, feedparser, and requests.

## Usage
`python main.py -u <feed-or-api-url> [params]`

Example: `python main.py -u https://example.com/vuln-feed.xml -p High -d 365`

## Parameters
- `-h`: Show help message and exit
- `-u`: URL of the RSS feed or API endpoint for vulnerability reports. Required.
- `-p`: Vulnerability priority to filter for, for example High or Critical (default: High).
- `-k`: Comma-separated list of keywords to filter vulnerability descriptions.
- `-o`: Path to save the summarized report (optional).
- `-d`: Number of days to limit the vulnerability age to (default: 365).
- `-r`: Regex to extract the date from the description; the regex must have a named capture group called date.

## License
MIT License. See the LICENSE file in this repository for the full text.
