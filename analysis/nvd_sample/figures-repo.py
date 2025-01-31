import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file (update the file path if needed)
file_path = "target_repos_count.csv"  # Replace with your CSV file's path
data = pd.read_csv(file_path)

# Ensure the CSV contains 'TargetRepo' and 'Occurrences' columns
if 'TargetRepo' not in data.columns or 'Occurrences' not in data.columns:
    raise ValueError("The CSV file must contain 'TargetRepo' and 'Occurrences' columns.")

# Select the top 10 rows
top_10 = data.head(10)

# Extract the string after the slash (/) in the 'TargetRepo' column
top_10['TargetRepo'] = top_10['TargetRepo'].str.split('/').str[-1]

# Generate the bar chart
plt.figure(figsize=(10, 6))
plt.bar(top_10['TargetRepo'], top_10['Occurrences'], color='skyblue')
plt.xlabel('ML Repositories', fontsize=12)
plt.ylabel('Occurrences', fontsize=12)
#plt.title('Top 10 Target Repositories by Occurrences', fontsize=14)
plt.xticks(rotation=45, ha='right')
plt.tight_layout()

# Save the chart as an image
output_path = "top_10_target_repositories.png"  # Output file name
plt.savefig(output_path)
print(f"Bar chart saved as {output_path}")

# Display the chart (optional)
plt.show()
