import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file (update the file path if needed)
file_path = "target_repos_count.csv"  # Replace with your CSV file's path
data = pd.read_csv(file_path)

# Ensure the CSV contains a 'Category' column
if 'Category' not in data.columns:
    raise ValueError("The CSV file must contain a 'Category' column.")

# Count occurrences of each category
category_counts = data['Category'].value_counts()

for category in category_counts:
    print(category)

# Generate the bar chart
plt.figure(figsize=(10, 6))
bar_width = 0.5  # Set bar width (reduce to make bars narrower)

plt.bar(category_counts.index, category_counts.values, color='skyblue', width=bar_width)
plt.xlabel('Category', fontsize=14)
plt.ylabel('Occurrences', fontsize=14)
#plt.title('Occurrences by Category', fontsize=14)
plt.xticks(rotation=45, ha='right', fontsize=12)
plt.yticks(fontsize=12)
plt.tight_layout()

# Save the chart as an image
output_path = "category_occurrences.png"  # Output file name
plt.savefig(output_path)
print(f"Bar chart saved as {output_path}")

# Display the chart (optional)
plt.show()
