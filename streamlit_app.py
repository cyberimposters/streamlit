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

                if len(cols) != num_cols + 1:
                    st.warning(f"Skipping row with unexpected number of columns: {len(cols)} (expected {num_cols + 1})")
                    continue
                data.append([ele for ele in cols if ele])

            df = pd.DataFrame(data, columns=headers)

        else:
            vuln_detail = soup.find('tr', {'data-testid': 'vuln-row-0'})
            if vuln_detail:
                cve = vuln_detail.find('a', {'data-testid': 'vuln-detail-link-0'}).text.strip()
                summary = vuln_detail.find('p', {'data-testid': 'vuln-summary-0'}).text.strip()
                cvss_severity = vuln_detail.find('td', nowrap="nowrap").text.strip().replace('\n', ' ')

                data = [[cve, summary, cvss_severity]]
                headers = ['CVE', 'Summary', 'CVSS Severity']
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
    'https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=elasticsearch&results_type=overview&form_type=Basic&search_type=all&startIndex=20'
    # Add more URLs as needed
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

