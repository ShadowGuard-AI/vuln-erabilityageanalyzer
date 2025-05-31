import argparse
import logging
import requests
import feedparser
import html2text
from datetime import datetime
from dateutil import parser
import re
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes vulnerability reports and calculates the average and maximum age of reported vulnerabilities.")
    parser.add_argument("-u", "--url", required=True, help="URL of the RSS feed or API endpoint for vulnerability reports.")
    parser.add_argument("-p", "--priority", type=str, default="High", help="Vulnerability priority to filter for (e.g., High, Critical).")
    parser.add_argument("-k", "--keywords", type=str, help="Comma-separated list of keywords to filter vulnerability descriptions.")
    parser.add_argument("-o", "--output", type=str, help="Path to save the summarized report (optional).")
    parser.add_argument("-d", "--days", type=int, default=365, help="Number of days to limit the vulnerability age to.")
    parser.add_argument("-r", "--regex", type=str, help="Regex to extract the date, the regex should have a named capture group 'date'")
    return parser.parse_args()

def fetch_vulnerability_reports(url):
    """
    Fetches vulnerability reports from the given URL, handling both RSS feeds and API endpoints.

    Args:
        url (str): URL of the RSS feed or API endpoint.

    Returns:
        list: A list of vulnerability report entries.  Returns None on failure.
    """
    try:
        if url.lower().endswith(('.rss', '.xml')):
            # Handle RSS feed
            logging.info(f"Fetching RSS feed from: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            feed = feedparser.parse(response.text)
            return feed.entries
        else:
            # Handle API endpoint (assuming JSON)
            logging.info(f"Fetching API data from: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()  # Assuming API returns JSON
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching vulnerability reports from {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred fetching data from {url}: {e}")
        return None

def extract_date_from_description(description, regex):
        """
        Extracts the date from the vulnerability description based on the provided regex.

        Args:
            description (str): The vulnerability description text.
            regex (str): The regular expression to use for date extraction.  Must have a named group called 'date'.

        Returns:
            datetime: The extracted date as a datetime object, or None if extraction fails.
        """
        try:
            match = re.search(regex, description)
            if match:
                date_string = match.group("date")
                return parser.parse(date_string)
            else:
                return None
        except Exception as e:
            logging.warning(f"Failed to extract date using regex: {e}")
            return None

def analyze_vulnerability_ages(reports, priority="High", keywords=None, max_age_days=365, date_regex=None):
    """
    Analyzes vulnerability reports and calculates the average and maximum age.

    Args:
        reports (list): A list of vulnerability report entries.
        priority (str): The vulnerability priority to filter for.
        keywords (str): Comma-separated list of keywords to filter descriptions.
        max_age_days (int): Maximum age of vulnerabilities to consider (in days).

    Returns:
        tuple: A tuple containing the average age (in days), maximum age (in days), and a list of high-priority vulnerabilities.  Returns (None, None, []) if there is an error.
    """
    today = datetime.now()
    ages = []
    high_priority_vulnerabilities = []

    if keywords:
        keywords_list = [k.strip().lower() for k in keywords.split(',')]
    else:
        keywords_list = []

    try:
        for report in reports:
            # Extract information based on common fields in RSS/API data
            title = report.get('title', '').lower()
            description = report.get('description', '').lower()
            link = report.get('link', '')
            published_date = None

            # Prioritize 'published' or 'pubDate' if available, otherwise try to extract from description
            if 'published' in report:
                try:
                    published_date = parser.parse(report['published'])
                except Exception as e:
                    logging.warning(f"Failed to parse 'published' date: {e}")
                    published_date = None
            elif 'pubDate' in report:
                try:
                    published_date = parser.parse(report['pubDate'])
                except Exception as e:
                    logging.warning(f"Failed to parse 'pubDate' date: {e}")
                    published_date = None

            # If published date is still None, attempt to extract from the description using regex
            if published_date is None and date_regex:
                published_date = extract_date_from_description(description, date_regex)


            if published_date:
                age = (today - published_date).days
            else:
                logging.warning(f"Could not determine the date for vulnerability {title}. Skipping.")
                continue

            # Filter based on priority and keywords
            if priority.lower() in title or priority.lower() in description:
                if not keywords_list or any(keyword in description for keyword in keywords_list) or any(keyword in title for keyword in keywords_list):
                    if age <= max_age_days:
                        ages.append(age)
                        high_priority_vulnerabilities.append({
                            'title': report.get('title', 'N/A'),
                            'description': report.get('description', 'N/A'),
                            'link': link,
                            'age': age,
                            'published_date': published_date.strftime("%Y-%m-%d") if published_date else "N/A"
                        })
        if ages:
            average_age = sum(ages) / len(ages)
            max_age = max(ages)
            return average_age, max_age, high_priority_vulnerabilities
        else:
            logging.info("No vulnerabilities found matching the criteria.")
            return None, None, []
    except Exception as e:
        logging.error(f"An error occurred during vulnerability analysis: {e}")
        return None, None, []

def generate_report(average_age, max_age, vulnerabilities, output_path=None):
    """
    Generates a report summarizing the vulnerability analysis.

    Args:
        average_age (float): The average age of vulnerabilities.
        max_age (int): The maximum age of vulnerabilities.
        vulnerabilities (list): A list of high-priority vulnerabilities.
        output_path (str): Path to save the report (optional).
    """
    report = f"""
    Vulnerability Analysis Report
    ------------------------------
    Average Vulnerability Age: {average_age:.2f} days
    Maximum Vulnerability Age: {max_age} days

    High-Priority Vulnerabilities:
    ------------------------------
    """
    if not vulnerabilities:
        report += "No High-Priority Vulnerabilities Found.\n"
    else:
        for vuln in vulnerabilities:
            report += f"""
    Title: {vuln['title']}
    Description: {vuln['description']}
    Link: {vuln['link']}
    Age: {vuln['age']} days
    Published Date: {vuln['published_date']}
    ------------------------------
    """

    print(report)  # Print to console
    if output_path:
        try:
            with open(output_path, "w") as f:
                f.write(report)
            logging.info(f"Report saved to: {output_path}")
        except Exception as e:
            logging.error(f"Error saving report to {output_path}: {e}")

def main():
    """
    Main function to orchestrate the vulnerability analysis.
    """
    args = setup_argparse()

    # Input validation (example)
    if not args.url:
        logging.error("URL is required.")
        sys.exit(1)

    reports = fetch_vulnerability_reports(args.url)
    if reports is None:
        sys.exit(1) # Exit if no reports are fetched.

    average_age, max_age, vulnerabilities = analyze_vulnerability_ages(reports, args.priority, args.keywords, args.days, args.regex)

    if average_age is not None and max_age is not None:
         generate_report(average_age, max_age, vulnerabilities, args.output)
    else:
        logging.warning("No report generated due to missing analysis data.")


if __name__ == "__main__":
    main()