import pandas as pd


# Function to update manual analysis based on GPT analysis
def update_manual_analysis(manual_file, gpt_file, output_file):
    # Load the manual analysis and GPT analysis CSV files
    manual_df = pd.read_csv(manual_file)
    gpt_df = pd.read_csv(gpt_file)

    # Loop through rows in the manual_df to find those with empty 'Related Attacks'
    for index, row in manual_df.iterrows():
        if pd.isna(row['Related attacks']) or row['Related attacks'] == 'Unknown':
            # Find the matching description in gpt_df
            matching_row = gpt_df[gpt_df['Description'] == row['Description']]

            if not matching_row.empty:
                # If a match is found, update 'Related attacks' in manual_df with the value from gpt_df
                manual_df.at[index, 'Related attacks'] = matching_row.iloc[0]['Related attacks']

    # Save the updated DataFrame to a new CSV file
    manual_df.to_csv(output_file, index=False)

    print(f"Updated manual analysis file saved as '{output_file}'.")


# File paths for the CSV files
manual_file = 'nvd-fixed-fixed-FINAL-before_after_issue_link.csv'  # Replace with the path to the manual analysis CSV
gpt_file = 'FINAL_updated_manual_analysis-issue_link_nvd.csv'  # Replace with the path to the GPT analysis CSV
output_file = 'nvd-threats_issue_link.csv'  # Path where the updated file will be saved

# Call the function to update manual analysis
update_manual_analysis(manual_file, gpt_file, output_file)
