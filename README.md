# vuln-erabilityAgeAnalyzer
Analyzes vulnerability reports and calculates the average and maximum age of reported vulnerabilities, providing insights into reporting lag and overall vulnerability management effectiveness. Uses `dateutil` for parsing dates. - Focused on Fetches vulnerability reports (e.g., NVD, Vendor Security Advisories) via RSS feeds or API, extracts relevant information (vulnerability description, affected versions, CVSS score), and generates concise summaries, helping security teams quickly prioritize remediation efforts. Focuses on identifying and summarizing *high-priority* vulnerabilities based on configurable criteria.

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-erabilityageanalyzer`

## Usage
`./vuln-erabilityageanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: URL of the RSS feed or API endpoint for vulnerability reports.
- `-p`: No description provided
- `-k`: Comma-separated list of keywords to filter vulnerability descriptions.
- `-o`: No description provided
- `-d`: Number of days to limit the vulnerability age to.
- `-r`: Regex to extract the date, the regex should have a named capture group 

## License
Copyright (c) ShadowStrikeHQ
