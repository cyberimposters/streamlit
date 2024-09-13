import requests
from bs4 import BeautifulSoup
import pandas as pd
import streamlit as st
import re
import concurrent.futures

# Pre-compile regex patterns
affected_versions_pattern = re.compile(r'\d{1}[.]\d{1,2}[.]\d{1,2}|\d{2}[.]\d{1}[.]\d{1}')
announcement_pattern = re.compile(r'ESA-\d{4}-\d{1,2}')

# Create a session to reuse connections
session = requests.Session()

# Software map for efficient string matching
software_map = {
    'elasticsearch': 'Elasticsearch',
    'logstash': 'Logstash',
    'jdk': 'Oracle JDK',
    'kibana': 'Kibana'
}

def scrape_nvd_page(url):
    response = session.get(url)
    response.raise_for_status()

    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract data from the table
    table = soup.find('table', {'data-testid': 'vuln-results-table'})
    if not table:
        return pd.DataFrame()

    data = []
    for row in table.find_all('tr'):
        cols = row.find_all('td')
        if len(cols) == 2:
            vuln_id_link = row.find('th').find('a')
            vuln_id = vuln_id_link.text if vuln_id_link else None
            summary = cols[0].text.strip()
            cvss_severity = cols[1].text.strip()

            # Extract affected versions
            affected_versions_match = affected_versions_pattern.findall(summary)
            affected_versions = ', '.join(affected_versions_match) if affected_versions_match else None

            # Identify the software from the URL
            software = 'Unknown'
            for key, value in software_map.items():
                if key in url.lower():
                    software = value
                    break

            # Extract the announcement if present
            announcement_match = announcement_pattern.search(summary)
            announcement = announcement_match.group(0) if announcement_match else None

            data.append([vuln_id, summary, cvss_severity, affected_versions, software, announcement])

    return pd.DataFrame(data, columns=['Vuln ID', 'Summary', 'CVSS Severity', 'Affected Versions', 'Software', 'Announcement'])

def get_cve_details(vuln_id):
    # Placeholder for actual logic to get CVE details
    return {"Vuln ID": vuln_id, "Details": "CVE details placeholder"}

# Define the search queries and their pagination limits
queries = {
    "elasticsearch": 100,  # Up to startIndex 80
    "kibana": 100,         # Up to startIndex 60
    "logstash": 100,       # Up to startIndex 20
    "Oracle GraalVM for JDK": 20  # Up to startIndex 20, note the phrase queryType
}

# Generate URLs based on queries and pagination
urls = []
for query, max_index in queries.items():
    for start_index in range(0, max_index + 1, 20):  # Iterate in steps of 20
        url = f"https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query={query}&results_type=overview&form_type=Basic&search_type=all&startIndex={start_index}"
        if " " in query:  # Add queryType=phrase for queries with spaces
            url += "&queryType=phrase"
        urls.append(url)

# Scrape all URLs in parallel and combine the results
def scrape_all_urls(urls):
    all_data = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scrape_nvd_page, url) for url in urls]
        for future in concurrent.futures.as_completed(futures):
            try:
                all_data.append(future.result())
            except Exception as e:
                print(f"Error scraping URL: {e}")
    return pd.concat(all_data, ignore_index=True) if all_data else pd.DataFrame()

# Fetch all data in parallel
all_data = scrape_all_urls(urls)

# Drop duplicate rows based on 'Vuln ID'
all_data.drop_duplicates(subset=['Vuln ID'], inplace=True)

# Streamlit app
st.title("CVE Search Results")

# Display the table
st.dataframe(all_data)

# Add search functionality
search_term = st.text_input("Search in Summary:")
if search_term:
    filtered_data = all_data[all_data['Summary'].str.contains(search_term, case=False)]
    st.dataframe(filtered_data)

# Add functionality to view more details when a row is clicked (Updated)
selected_rows = st.data_editor(all_data, num_rows="dynamic")
if selected_rows is not None and not selected_rows.empty:
    selected_vuln_id = selected_rows.iloc[0]['Vuln ID']
    details = get_cve_details(selected_vuln_id)
    st.write(f"Details for {selected_vuln_id}:")
    st.json(details)
