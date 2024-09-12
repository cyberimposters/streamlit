import requests
from bs4 import BeautifulSoup
import pandas as pd
import streamlit as st
import re

def scrape_nvd_page(url):
    response = requests.get(url)
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

            # Extract affected versions using regex
            affected_versions_match = re.findall(r'\d{1}[.]\d{1,2}[.]\d{1,2}|\d{2}[.]\d{1}[.]\d{1}', summary)  # Updated regex pattern
            affected_versions = ', '.join(affected_versions_match) if affected_versions_match else None

            # Identify the software from the URL
            if 'elasticsearch' in url.lower():
                software = 'Elasticsearch'
            elif 'logstash' in url.lower():
                software = 'Logstash'
            elif 'jdk' in url.lower():
                software = 'Oracle JDK'
            else:
                software = 'Unknown'

            # Extract the announcement if present
            announcement_match = re.search(r'ESA-\d{4}-\d{1,2}', summary)
            announcement = announcement_match.group(0) if announcement_match else None

            data.append([vuln_id, summary, cvss_severity, affected_versions, software, announcement])

    return pd.DataFrame(data, columns=['Vuln ID', 'Summary', 'CVSS Severity', 'Affected Versions', 'Software', 'Announcement'])

def get_cve_details(vuln_id):
    url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    # ... (Extract more details as needed from the CVE detail page)
    return  # Return the extracted details

# URLs to scrape
urls = [
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=0",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=20",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=40",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=60",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=80",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=0",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=20",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=40",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=60",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=logstash&results_type=overview&form_type=Basic&search_type=all&startIndex=0",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=logstash&results_type=overview&form_type=Basic&search_type=all&startIndex=20",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=Oracle+GraalVM+for+JDK&results_type=overview&form_type=Basic&search_type=all&queryType=phrase&startIndex=0",
    "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=Oracle+GraalVM+for+JDK&results_type=overview&form_type=Basic&search_type=all&queryType=phrase&startIndex=20"
]

# Scrape all URLs and combine the results
all_data = pd.DataFrame()
for url in urls:
    page_data = scrape_nvd_page(url)
    all_data = pd.concat([all_data, page_data], ignore_index=True)

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
#selected_row = st.data_editor(all_data, num_rows="dynamic")
#if selected_row:
#    vuln_id = selected_row['Vuln ID']
#    details = get_cve_details(vuln_id)
    # ... (Display the extracted details in Streamlit)
