import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.colors as mcolors

# Load the CSV file
data = pd.read_csv('FINAL_updated_manual_analysis_reponame_nvd.csv')

# Simplify TargetRepo names by keeping only the part after the last slash
data['TargetRepo'] = data['TargetRepo'].apply(lambda x: x.split('/')[-1])

# Count the occurrences of vulnerabilities per repository
top_repos = data['TargetRepo'].value_counts().head(10)

# Define attack types and create a colormap
all_attacks = [
    'Denial of Service (DoS)', 'Improper Input Validation', 'Heap-based Buffer Overflow',
    'NULL pointer dereference', 'SQL injection', 'Use-after-free', 'Bypass authentication',
    'Remote code execution (RCE)', 'Arbitrary code', 'Prototype Pollution',
    'Information disclosure', 'Privilege escalation', 'XML Injection'
]
num_colors = len(all_attacks)
colormap = plt.cm.get_cmap('tab20', num_colors)  # Use 'tab20' colormap

# Create a color map for attack types
color_map = {attack: mcolors.rgb2hex(colormap(i)) for i, attack in enumerate(all_attacks)}

# Initialize the plot
plt.figure(figsize=(12, 8))

# Track displayed attack types
displayed_attacks = set()
atacks = []

# Plot data for each top repository
for repo in top_repos.index:
    # Filter rows for the current repository
    repo_data = data[data['TargetRepo'] == repo]

    # Count occurrences of each attack type
    attack_counts = (
        repo_data['Related attacks']
        .dropna()
        .str.replace(r"\battack\b", "", case=False, regex=True)  # Remove the word 'attack'
        .str.split(',')
        .explode()
        .apply(lambda x: x.strip())
        .value_counts()
        .head(5)  # Limit to top 5 attack types
    )

    # Add bars for each attack type
    for attack in attack_counts.index:
        plt.bar(
            repo,
            attack_counts[attack],
            color=color_map[attack],
            edgecolor='black',
            width=0.6,  # Reduce bar width
            label=attack if attack not in displayed_attacks else ""
        )
        displayed_attacks.add(attack)
        if attack not in atacks:
            atacks.append(attack)

# Customize the chart
plt.xlabel('ML Repositories', fontsize=14)  # Increase x-axis label font size
plt.ylabel('Occurrences', fontsize=14)     # Increase y-axis label font size
plt.xticks(rotation=45, ha='right', fontsize=12)  # Adjust x-tick font size
plt.yticks(fontsize=12)  # Adjust y-tick font size
plt.legend(title='Attack Types', bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=10, title_fontsize=12)  # Customize legend

# Ensure a tight layout
plt.tight_layout()

# Save the chart
plt.savefig('vulnerability_analysis_combined.png')
plt.show()

print(atacks)
