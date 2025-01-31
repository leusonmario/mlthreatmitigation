import pandas as pd
import re

def find_and_group_unique_cve_patterns(csv_file, output_file):
    try:
        # Read the CSV file into a Pandas DataFrame
        df = pd.read_csv(csv_file)

        # Define the regex pattern for CVE identifiers
        cve_pattern = r'CVE-\d{4}-\d{4,7}'

        # Check if the required columns exist
        required_columns = ['title', 'body', 'comments', 'repository']
        for col in required_columns:
            if col not in df.columns:
                print(f"The required column '{col}' is not in the CSV file.")
                return

        # List to store the results
        results = []

        # Iterate over each row in the DataFrame
        for index, row in df.iterrows():
            # Initialize an empty set to store unique CVE matches for this row
            unique_cve_matches = set()

            # Check each relevant cell (title, body, comments) for CVE pattern matches
            for col in ['title', 'body', 'comments']:
                cell = row[col]
                if isinstance(cell, str):  # Ensure the cell value is a string
                    # Find all matches in the cell and add them to the set (ensuring uniqueness)
                    unique_cve_matches.update(re.findall(cve_pattern, cell))

            # If there are any unique CVE matches, add them to the results list
            for cve in unique_cve_matches:
                # Append a dictionary to results with the CVE match, repository, and selected row data
                results.append({
                    'Index': index,
                    'CVE': cve,
                    'title': row['title'],
                    #'body': row['body'],
                    #'comments': row['comments'],
                    'repository': row['repository'],
                    'date': row['created_at'],
                    'Issue_ID': row['url']
                })

        # Create a new DataFrame from the results list
        grouped_df = pd.DataFrame(results)

        # Save the grouped DataFrame to a new CSV file
        grouped_df.to_csv(output_file, index=False)

        print(f"Grouped unique CVE data with associated repository has been saved to {output_file}.")

    except FileNotFoundError:
        print(f"The file {csv_file} does not exist.")
    except pd.errors.EmptyDataError:
        print("The file is empty.")
    except pd.errors.ParserError:
        print("There was an error parsing the file.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Specify the input CSV file name and output CSV file name
    input_csv_file = '../sample/output_no_duplicates.csv'
    output_csv_file = 'grouped_unique_cve_patterns_final_before_after.csv'

    #input_csv_file = '../documents/vulnerability_issues.csv'
    #input_csv_file = '../analysis/final_vulnerabilities.csv'
    #output_csv_file = 'grouped_unique_cve_patterns-before.csv'
    #output_csv_file = 'grouped_unique_cve_patterns-fixed-FINAL.csv.csv'

    # Find and group unique CVE patterns in the input CSV file
    find_and_group_unique_cve_patterns(input_csv_file, output_csv_file)
