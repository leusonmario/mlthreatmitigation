import pandas as pd
from collections import defaultdict

# Function to process the CSV file and generate the required output
def process_cpe_dependencies(input_file, output_file):
    # Load the CSV file into a pandas DataFrame
    df = pd.read_csv(input_file)

    # Initialize a dictionary to store the data grouped by 'CPE dependency name'
    cpe_data = defaultdict(lambda: {
        'severity': set(),
        'repos': set(),
        'cve_ids': defaultdict(int),  # Store CVE IDs and their occurrences
    })

    # Loop through each row in the DataFrame
    for _, row in df.iterrows():
        cpe_name = row['CPE dependency name ']
        cve_id = row['CVE ID']
        severity = row['CVE severity']
        repo = row['TargetRepo']

        # Update the data structure for the current CPE dependency name
        cpe_data[cpe_name]['severity'].add(severity)
        cpe_data[cpe_name]['repos'].add(repo)
        cpe_data[cpe_name]['cve_ids'][cve_id] += 1  # Increment the count for this CVE ID

    # Prepare a list to store the output rows
    output_rows = []

    # Prepare the output data
    for cpe_name, data in cpe_data.items():
        cve_ids = list(data['cve_ids'].keys())  # List of unique CVE IDs
        cve_id_count = sum(data['cve_ids'].values())  # Total number of CVE ID occurrences
        row = {
            'CPE dependency name': cpe_name,
            'CVE ID': ', '.join(cve_ids),  # Join CVE IDs with commas
            'Number of CVE ID occurrences': len(cve_ids),  # Total occurrences of CVE IDs
            'CVE severity': ', '.join(data['severity']),  # Join severity with commas
            'Number of Issues': len(data['repos']),
            'Issues': ', '.join(data['repos'])  # Join repositories with commas
        }
        output_rows.append(row)

    # Create a DataFrame from the output rows
    output_df = pd.DataFrame(output_rows)

    # Save the DataFrame to the output CSV file
    output_df.to_csv(output_file, index=False)

    print(f"Results saved to '{output_file}'.")

# File paths for the input and output CSV files
input_file = 'FINAL_updated_manual_analysis_reponame_nvd.csv'  # Replace with the path to your input CSV file
output_file = 'cpe_dependency_reponame.csv'  # Path where the output will be saved

# Call the function to process the CSV file and generate the output
process_cpe_dependencies(input_file, output_file)
