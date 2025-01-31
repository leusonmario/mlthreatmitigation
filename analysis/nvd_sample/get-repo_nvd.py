import pandas as pd
from collections import Counter

# Function to collect unique target repositories and count occurrences
def count_target_repos(input_file, output_file):
    # Load the CSV file into a pandas DataFrame
    df = pd.read_csv(input_file)

    # Create an empty list to store all target repositories
    all_target_repos = []

    # Loop through the 'TargetRepo' column
    for repo in df['TargetRepo'].dropna():
        # Add each repo to the list
        all_target_repos.append(repo.strip())

    # Count the occurrences of each unique target repository
    repo_counts = Counter(all_target_repos)

    # Create a DataFrame from the counts
    repo_counts_df = pd.DataFrame(repo_counts.items(), columns=['TargetRepo', 'Occurrences'])

    # Sort by occurrences in descending order
    repo_counts_df = repo_counts_df.sort_values(by='Occurrences', ascending=False)

    # Save the result to a new CSV file
    repo_counts_df.to_csv(output_file, index=False)

    print(f"Results saved to '{output_file}'.")

# File paths for the input and output CSV files
input_file = 'FINAL_updated_manual_analysis_reponame_nvd.csv'  # Replace with the path to your input CSV file
output_file = 'target_repos_count.csv'  # Path where the output will be saved

# Call the function to count target repositories
count_target_repos(input_file, output_file)
