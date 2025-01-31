import pandas as pd
from collections import Counter

# Function to collect unique related attacks and count occurrences
def count_related_attacks(input_file, output_file):
    # Load the CSV file into a pandas DataFrame
    df = pd.read_csv(input_file)

    # Create an empty list to store all related attacks
    all_related_attacks = []

    # Loop through the 'Related attacks' column
    for attacks in df['Related attacks'].dropna():
        # Split by comma, strip extra spaces, and add to the list
        attacks_list = [attack.strip() for attack in attacks.split(',')]
        all_related_attacks.extend(attacks_list)

    # Count the occurrences of each unique related attack
    attack_counts = Counter(all_related_attacks)

    # Create a DataFrame from the counts
    attack_counts_df = pd.DataFrame(attack_counts.items(), columns=['Related attack', 'Occurrences'])

    # Sort by occurrences in descending order
    attack_counts_df = attack_counts_df.sort_values(by='Occurrences', ascending=False)

    # Save the result to a new CSV file
    attack_counts_df.to_csv(output_file, index=False)

    print(f"Results saved to '{output_file}'.")

# File paths for the input and output CSV files
input_file = 'FINAL_updated_manual_analysis_reponame_nvd.csv'  # Replace with the path to your input CSV file
output_file = 'related_attacks_count.csv'  # Path where the output will be saved

# Call the function to count related attacks
count_related_attacks(input_file, output_file)
