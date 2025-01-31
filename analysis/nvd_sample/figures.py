import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file (update the file path if needed)
file_path = "related_attacks_count.csv"  # Replace with your CSV file's path
data = pd.read_csv(file_path)

# Ensure the CSV contains 'Related attack' and 'Occurrences' columns
if 'Related attack' not in data.columns or 'Occurrences' not in data.columns:
    raise ValueError("The CSV file must contain 'Related attack' and 'Occurrences' columns.")

# Select the top 10 rows
top_10 = data.head(10)

# Remove the word 'attack' from the 'Related attack' names
top_10['Related attack'] = top_10['Related attack'].str.replace(r'\battack\b', '', regex=True).str.strip()

# Generate the bar chart
plt.figure(figsize=(10, 6))
bar_width = 0.5  # Set bar width (reduce to make bars narrower)
plt.bar(top_10['Related attack'], top_10['Occurrences'], color='skyblue', width=bar_width)
plt.xlabel('Vulnerability Types', fontsize=14)
plt.ylabel('Number of Occurrences', fontsize=14)
#plt.title('Top 10 Related Attacks by Occurrences', fontsize=14)
plt.xticks(rotation=45, ha='right', fontsize=12)
plt.yticks(fontsize=12)
plt.tight_layout()

# Save the chart as an image
output_path = "top_10_related_attacks.png"  # Output file name
plt.savefig(output_path)
print(f"Bar chart saved as {output_path}")

# Display the chart (optional)
plt.show()
