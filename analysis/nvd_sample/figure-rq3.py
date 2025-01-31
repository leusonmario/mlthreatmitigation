import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file
data = pd.read_csv('FINAL_updated_manual_analysis_reponame_nvd.csv')

# Simplify TargetRepo names by keeping only the part after the last slash
data['TargetRepo'] = data['TargetRepo'].apply(lambda x: x.split('/')[-1])

# Count the occurrences of vulnerabilities per repository
top_repos = data['TargetRepo'].value_counts().head(10)

# Prepare a unique color map for attack types
all_attacks = data['Related attacks'].dropna().str.split(',').explode().unique()
color_map = {attack: plt.cm.tab20(i / len(all_attacks)) for i, attack in enumerate(all_attacks)}

# Initialize the plot
plt.figure(figsize=(12, 8))

# Track displayed attack types
displayed_attacks = set()

# Plot data for each top repository
for repo in top_repos.index:
    # Filter rows for the current repository
    repo_data = data[data['TargetRepo'] == repo]

    # Split the "Related attacks" column into individual attacks and count occurrences
    attack_counts = repo_data['Related attacks'].dropna().str.split(',').explode().value_counts().head(5)

    # Add the data to the chart
    for attack in attack_counts.index:
        plt.bar(repo, attack_counts[attack], color=color_map[attack], edgecolor='black',
                label=attack if attack not in displayed_attacks else "")
        displayed_attacks.add(attack)

# Customize the chart
plt.title('Top 10 Repositories and Their Top 5 Attack Types', fontsize=16)
plt.xlabel('Repositories', fontsize=14)
plt.ylabel('Number of Occurrences', fontsize=14)
plt.xticks(rotation=45, ha='right')
plt.legend(title='Attack Types', bbox_to_anchor=(1.05, 1), loc='upper left')
plt.tight_layout()

# Save the chart
plt.savefig('vulnerability_analysis_combined.png')
plt.show()
