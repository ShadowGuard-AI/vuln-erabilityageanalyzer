import argparse
import logging
import requests
import feedparser
from datetime import datetime, timezone
from dateutil import parser
import re
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
            data = response.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                # Documented wrapper keys: an object wrapping the list of
                # reports under one of these keys is unwrapped.
                for key in ("results", "vulnerabilities", "entries", "reports", "items"):
                    if isinstance(data.get(key), list):
                        return data[key]
                logging.error(f"API response from {url} is a JSON object with no list of reports under a known wrapper key (results, vulnerabilities, entries, reports, items); treating it as a fetch error.")
                return None
            logging.error(f"API response from {url} has an unsupported shape ({type(data).__name__}); treating it as a fetch error.")
            return None
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
        tuple: A tuple containing the average age (in days), maximum age (in days), a list of high-priority vulnerabilities, and a stats dict counting future-dated entries excluded and entries skipped because their date could not be determined (naming the skipped entries). Returns (None, None, [], stats) when nothing matches.
    """
    today = datetime.now(timezone.utc)
    ages = []
    high_priority_vulnerabilities = []
    stats = {"future_excluded": 0, "skipped": 0, "skipped_titles": []}

    if keywords:
        keywords_list = [k.strip().lower() for k in keywords.split(',')]
    else:
        keywords_list = []

    for report in reports:
        title_for_log = "unknown entry"
        try:
            if not hasattr(report, "get"):
                stats["skipped"] += 1
                stats["skipped_titles"].append(str(report)[:80])
                logging.warning(f"Skipping entry that is not a report object: {str(report)[:80]}")
                continue
            title_for_log = str(report.get('title', 'N/A'))
            title = str(report.get('title', '')).lower()
            description = str(report.get('description', '')).lower()
            link = report.get('link', '')
            published_date = None

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

            if published_date is None and date_regex:
                published_date = extract_date_from_description(description, date_regex)

            if published_date is None:
                stats["skipped"] += 1
                stats["skipped_titles"].append(title_for_log)
                logging.warning(f"Could not determine the date for vulnerability {title_for_log}. Skipping this entry.")
                continue

            # Filter based on priority and keywords
            # Priority is a substring test, not a field. The word high
            # inside another word, or a passing mention in the text,
            # counts the report as high priority, and a report whose
            # feed stores priority in its own field is only found when
            # the word also appears in the title or description.
            if priority.lower() not in title and priority.lower() not in description:
                continue
            if keywords_list and not any(keyword in description for keyword in keywords_list) and not any(keyword in title for keyword in keywords_list):
                continue

            # Normalize to a single basis: aware dates are converted to
            # UTC and naive dates are taken as UTC, so the subtraction
            # against the aware UTC now cannot raise a TypeError.
            if published_date.tzinfo is None:
                published_utc = published_date.replace(tzinfo=timezone.utc)
            else:
                published_utc = published_date.astimezone(timezone.utc)
            age = (today - published_utc).days
            if age < 0:
                stats["future_excluded"] += 1
                logging.warning(f"Excluding future-dated entry {title_for_log} (age {age} days).")
                continue
            if age <= max_age_days:
                ages.append(age)
                high_priority_vulnerabilities.append({
                    'title': report.get('title', 'N/A'),
                    'description': report.get('description', 'N/A'),
                    'link': link,
                    'age': age,
                    'published_date': published_utc.strftime("%Y-%m-%d")
                })
        except Exception as e:
            stats["skipped"] += 1
            stats["skipped_titles"].append(title_for_log)
            logging.warning(f"Skipping entry {title_for_log} after an error: {e}")
            continue

    if ages:
        average_age = sum(ages) / len(ages)
        max_age = max(ages)
        return average_age, max_age, high_priority_vulnerabilities, stats
    logging.info("No vulnerabilities found matching the criteria.")
    return None, None, [], stats

def generate_report(average_age, max_age, vulnerabilities, output_path=None, stats=None):
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
    if stats:
        report += f"Future-dated entries excluded: {stats.get('future_excluded', 0)}\n"
        report += f"Entries skipped (date could not be determined): {stats.get('skipped', 0)}\n"
        for skipped_title in stats.get('skipped_titles', []):
            report += f"Skipped entry: {skipped_title}\n"
        report += "\n"
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

def generate_no_matches_report(stats, output_path=None):
    """Write a report that states plainly that no entries matched."""
    report = "Vulnerability Analysis Report\n------------------------------\nStatus: No matches. No vulnerabilities matched the criteria, so no age statistics were computed.\n"
    if stats:
        report += f"Future-dated entries excluded: {stats.get('future_excluded', 0)}\n"
        report += f"Entries skipped (date could not be determined): {stats.get('skipped', 0)}\n"
        for skipped_title in stats.get('skipped_titles', []):
            report += f"Skipped entry: {skipped_title}\n"
    print(report)
    if output_path:
        try:
            with open(output_path, "w") as f:
                f.write(report)
            logging.info(f"Report saved to: {output_path}")
        except Exception as e:
            logging.error(f"Error saving report to {output_path}: {e}")
    return report


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

    average_age, max_age, vulnerabilities, stats = analyze_vulnerability_ages(reports, args.priority, args.keywords, args.days, args.regex)

    if average_age is not None and max_age is not None:
         generate_report(average_age, max_age, vulnerabilities, args.output, stats)
    else:
        generate_no_matches_report(stats, args.output)
        if stats.get("skipped"):
            logging.error(f"Analysis incomplete: {stats['skipped']} entry or entries could not be dated: {', '.join(stats['skipped_titles'])}")
        logging.warning("No matching vulnerabilities: exiting non-zero so zero matching work is not reported as a completed analysis.")
        sys.exit(1)


if __name__ == "__main__":
    main()