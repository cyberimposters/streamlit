import requests
from bs4 import BeautifulSoup
import pandas as pd
import streamlit as st

def fetch_nvd_data(url):
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')

    # print(soup.prettify())  # Uncomment this to inspect the HTML structure if needed

    try:
        table = soup.find('table', {'data-testid': 'vuln-results-table'})

        # Extract column headers (dynamically adjust based on the first data row)
        first_row = table.find_all('tr')[1]  # Assuming the first row is the header row
        num_cols = len(first_row.find_all('td'))
        headers = [th.text.strip() for th in table.find_all('th')][:num_cols]

        # Extract data rows
        data = []
        for row in table.find_all('tr')[1:]:  # Start from the second row to skip the header
            cols = row.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            if len(cols) != num_cols:
                st.warning(f"Skipping row with unexpected number of columns: {len(cols)} (expected {num_cols})")
                continue
            data.append([ele for ele in cols if ele])

        # Create a DataFrame
        df = pd.DataFrame(data, columns=headers)

        # Add "Software Component" column based on URL
        if 'elasticsearch' in url.lower():
            df['Software Component'] = 'Elasticsearch'
        elif 'kibana' in url.lower():
            df['Software Component'] = 'Kibana'
        elif 'logstash' in url.lower():
            df['Software Component'] = 'Logstash'
        else:
            df['Software Component'] = 'Unknown'  # Handle other cases if needed

        # Extract all Elasticsearch versions from the 'Vuln ID' column using the new regex
        df['Affected Versions'] = df['Vuln ID'].str.findall(r'\d{1}[.]\d{1,2}[.]\d{1,2}').str.join(', ')

        return df

    except AttributeError:
        st.error("Error: Unable to find the results table. The NVD website structure may have changed.")
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

