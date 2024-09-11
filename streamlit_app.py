import requests
from bs4 import BeautifulSoup 
import pandas as pd
import streamlit as st

def fetch_nvd_data(url):
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')

    try:
        table = soup.find('table', {'data-testid': 'vuln-results-table'})

        if table:
            first_row = table.find_all('tr')[1]
            num_cols = len(first_row.find_all('td'))
            headers = [th.text.strip() for th in table.find_all('th')][:num_cols]

            if 'CVE' not in headers:
                headers.insert(0, 'CVE')

            data = []
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                cols = [ele.text.strip() for ele in cols]

                cve_link = cols[0].find('a')
                if cve_link:
                    cve = cve_link.text.strip()
                    cols.insert(0, cve)

                    # Fetch affected versions from the detail page
                    detail_url = 'https://nvd.nist.gov' + cve_link['href']
                    detail_response = requests.get(detail_url)
                    detail_response.raise_for_status()
                    detail_soup = BeautifulSoup(detail_response.content, 'html.parser')

                    # Extract affected versions (REPLACE THIS WITH ACTUAL CODE)
                    affected_versions_section = detail_soup.find('div', id='vulnConfigurationsDiv')  # Adjust if needed
                    if affected_versions_section:
                        affected_versions = affected_versions_section.find_all('a', {'data-testid': 'vuln-configuration-cpe-link'})  # Adjust if needed
                        affected_versions = [version.text.strip() for version in affected_versions]
                        cols.append(', '.join(affected_versions))
                    else:
                        cols.append('N/A')

                if len(cols) != num_cols + 2:
                    st.warning(f"Skipping row with unexpected number of columns: {len(cols)} (expected {num_cols + 2})")
                    continue
                data.append([ele for ele in cols if ele])

            headers.append('Affected Versions')
            df = pd.DataFrame(data, columns=headers)

        else:
            vuln_detail = soup.find('tr', {'data-testid': 'vuln-row-0'})
            if vuln_detail:
                cve = vuln_detail.find('a', {'data-testid': 'vuln-detail-link-0'}).text.strip()
                summary = vuln_detail.find('p', {'data-testid': 'vuln-summary-0'}).text.strip()
                cvss_severity = vuln_detail.find('td', nowrap="nowrap").text.strip().replace('\n', ' ')

                # Fetch affected versions from the detail page (for single result)
                detail_url = 'https://nvd.nist.gov' + vuln_detail.find('a', {'data-testid': 'vuln-detail-link-0'})['href']
                detail_response = requests.get(detail_url)
                detail_response.raise_for_status()
                detail_soup = BeautifulSoup(detail_response.content, 'html.parser')

                # Extract affected versions (REPLACE THIS WITH ACTUAL CODE)
                affected_versions_section = detail_soup.find('div', id='vulnConfigurationsDiv')  # Adjust if needed
                if affected_versions_section:
                    affected_versions = affected_versions_section.find_all('a', {'data-testid': 'vuln-configuration-cpe-link'})  # Adjust if needed
                    affected_versions = [version.text.strip() for version in affected_versions]
                    affected_versions_str = ', '.join(affected_versions)
                else:
                    affected_versions_str = 'N/A'

                data = [[cve, summary, cvss_severity, affected_versions_str]]
                headers = ['CVE', 'Summary', 'CVSS Severity', 'Affected Versions']
                df = pd.DataFrame(data, columns=headers)
            else:
                st.error("No vulnerability details found on the page.")
                return None

        # Add "Software Component" column based on URL
        if 'elasticsearch' in url.lower():
            df['Software Component'] = 'Elasticsearch'
        elif 'kibana' in url.lower():
            df['Software Component'] = 'Kibana'
        elif 'logstash' in url.lower():
            df['Software Component'] = 'Logstash'
        else:
            df['Software Component'] = 'Unknown'

        return df

    except AttributeError:
        st.error("Error: The NVD website structure may have changed.")
        return None
    except IndexError as e:
        st.error(f"Error processing table data: {e}")
        return None

# Streamlit app
st.title('NVD Vulnerability Search Results')

# URLs to fetch data from (all pages)
urls = [
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=0',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=20',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=40',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=60',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=80',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=0',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=20',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=40',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=kibana&results_type=overview&form_type=Basic&search_type=all&startIndex=60',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=logstash&results_type=overview&form_type=Basic&search_type=all&startIndex=0',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=logstash&results_type=overview&form_type=Basic&search_type=all&startIndex=20',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=Oracle+GraalVM+for+JDK&results_type=overview&form_type=Basic&search_type=all&queryType=phrase&startIndex=0',
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=Oracle+GraalVM+for+JDK&results_type=overview&form_type=Basic&search_type=all&queryType=phrase&startIndex=20'
]

# Fetch and combine data from all URLs
all_data = pd.DataFrame()
for url in urls:
    df = fetch_nvd_data(url)
    if df is not None:
        all_data = pd.concat([all_data, df])

# Display the combined DataFrame
if not all_data.empty:
    st.dataframe(all_data)
else:
    st.error("No data found. Please check the URLs or the NVD website structure.")
