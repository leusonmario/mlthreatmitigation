import pandas as pd
import openai

openai.api_key = ''  # OpenAI API key

categories = [
    'Heap-based Buffer Overflow', 'Stored Cross-Site Scripting (XSS) attack', 'Resource Management',
    'Improper Input Validation', 'Information disclosure attack', 'Prototype Pollution attack',
    'Denial of Service (DoS)', 'Remote code execution (RCE) attack', 'Cross-site request forgery (CSRF) attack',
    'Use-after-free attack', 'Bypass authentication attack', 'SQL injection attack', 'Privilege escalation attack',
    'XML Injection attack', 'NULL pointer dereference attack', 'Arbitrary code attack'
]

input_file = 'unknown-cases.csv'  # Replace with your actual input CSV file path
output_file = 'output_classified_file_unknown.csv'  # Replace with your desired output file path

df = pd.read_csv(input_file)


def classify_description(description):
    messages = [
        {"role": "system", "content": "You are a security classification assistant."},
        {"role": "user",
         "content": f"Classify the following description into one of these categories: {', '.join(categories)}\n\nDescription: {description}\n"
                    f"If none of the given categories fits, please, report a new category."
                    f"For that, report ONLY the name of the category."
                    f"Do not report additional comments."
                    f""
                    f"Category:"}
    ]

    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",  # Using GPT-4 model
        messages=messages,
        max_tokens=50,
        temperature=0.3,
        n=1,
    )

    category = response['choices'][0]['message']['content'].strip()

    return category

df['Related Attacks'] = df['Description'].apply(classify_description)

df.to_csv(output_file, index=False)

print(f"Classified results have been saved to '{output_file}'.")
