import argparse
import re
from openai import OpenAI
import logging
import os
import pickle
import random
import pandas as pd
import collections
import json

# Define CodeDocument structure
CodeDocument = collections.namedtuple(
    'CodeDocument',
    ['words', 'cls', 'project', 'CVE_ID', 'CWE_ID', 'commit', 'parent_commit', 'file_name', 'file_ID', 'function_ID', 'API_summary', 'API_sequence']
)

# Initialize logging
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Setup DeepSeek API client
def setup_deepseek_client(api_key):
    client = OpenAI(
        base_url='https://api.openai.com/v1',
        api_key=api_key
    )
    return client

# Read pickle file
def read_pickle(file_path, limit=None, shuffle=True):
    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    if limit is not None:
        contents = random.sample(contents, limit)
    if shuffle:
        random.shuffle(contents)
    return contents

# Initialize conversation context with system message
def initialize_conversation():
    return [
        {
            "role": "system",
            "content": "You are an expert vulnerability detection system. Provide precise and direct answers with explanations only when necessary."
        }
    ]

# Optimized multi-round model prediction
def get_multi_round_prediction(client, code_document, conversation_history):
    # Round 1: Provide a summary of code functionality, structure, and pointer analysis
    prompt_1 = (
        f"Code:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
        f"Please provide a detailed summary of the code's functionality, analyze the code structure, and locate all positions where pointers are constructed. "
        f"Also, identify all locations where pointers are dereferenced."
    )
    conversation_history.append({"role": "user", "content": prompt_1})
    logging.info(f"Prompt 1: {prompt_1}")

    response_1 = client.chat.completions.create(
        model="gpt-4o",
        messages=conversation_history,
        stream=False
    )
    conversation_history.append(response_1.choices[0].message)
    code_analysis = response_1.choices[0].message.content
    logging.info(f"Response 1: {code_analysis}")

    # Round 2: Based on the analysis, evaluate vulnerabilities
    prompt_2 = (
        f"Based on the analysis of the code: '{code_analysis}', evaluate whether the code has any significant vulnerabilities. "
        f"Answer 'yes' or 'no' to indicate if there is a significant risk. If there is a risk, please provide the specific reason."
    )
    conversation_history.append({"role": "user", "content": prompt_2})
    logging.info(f"Prompt 2: {prompt_2}")

    response_2 = client.chat.completions.create(
        model="gpt-4o",
        messages=conversation_history,
        stream=False
    )
    conversation_history.append(response_2.choices[0].message)
    logging.info(f"Response 2: {response_2.choices[0].message.content}")

    # Extract final output and ensure it only captures yes or no
    output = response_2.choices[0].message.content.strip().lower()
    logging.info(f"Raw model output: {output}")

    match = re.search(r'\b(yes|no)\b', output)
    result = match.group(1) if match else None

    if result == "yes":
        return 1, output
    elif result == "no":
        return 0, output
    return -1, None  # Indicates invalid prediction

# Detect vulnerability
def detect_vulnerability(client, code_document, callee_key="random_sampled_callees"):
    conversation_history = initialize_conversation()

    # Ensure the API_sequence uses the specified callee_key
    if callee_key in code_document.API_sequence:
        code_document = code_document._replace(API_sequence=code_document.API_sequence[callee_key])
    else:
        logging.warning(f"{callee_key} not found in API_sequence. Using default empty value.")
        code_document = code_document._replace(API_sequence="")

    prediction, model_output = get_multi_round_prediction(client, code_document, conversation_history)
    original_cls = 0 if code_document.cls == 0 else 1

    # Print original and predicted labels
    logging.info(f"Original Label: {original_cls}, Predicted Label: {prediction}")

    return prediction, original_cls, model_output

# Process dataset
def process_data(client, data, callee_key):
    results = []
    for code_document in data:
        prediction, original_label, prediction_output = detect_vulnerability(client, code_document, callee_key)
        result_data = {
            "words": code_document.words,
            "original_cls": original_label,
            "project": code_document.project,
            "CVE_ID": code_document.CVE_ID,
            "CWE_ID": code_document.CWE_ID,
            "commit": code_document.commit,
            "parent_commit": code_document.parent_commit,
            "file_name": code_document.file_name,
            "file_ID": code_document.file_ID,
            "function_ID": code_document.function_ID,
            "API_summary": code_document.API_summary,
            "API_sequence": code_document.API_sequence,
            "prediction_label": prediction,
            "model_output": prediction_output
        }
        results.append(result_data)
    return results

# Save results to JSON and Excel
def save_results(results, model_name, callee_key, output_dir="../../result"):
    os.makedirs(output_dir, exist_ok=True)

    base_filename = f"{model_name}_{callee_key}".replace("/", "_")
    json_file_path = os.path.join(output_dir, f'{base_filename}_results.json')
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')

    excel_file_path = os.path.join(output_dir, f'{base_filename}_results.xlsx')
    pd.DataFrame(results).to_excel(excel_file_path, index=False)

    logging.info(f"Results saved to {json_file_path} and {excel_file_path}")


# Main function
def main():
    parser = argparse.ArgumentParser(description="Vulnerability detection using ChatGPT-4o baseline.")
    parser.add_argument('--api_key', required=True, help='API key for DeepSeek or OpenAI')
    parser.add_argument('--callee_key', required=True, choices=[
        'All', 'API_sample', 'hierarchy_sample', 'Random_sample', 'similar_sample'
    ], help='Callee key type')
    args = parser.parse_args()

    setup_logging()
    client = setup_deepseek_client(api_key=args.api_key)

    model_name = "gpt-4o"
    data_path = '../../data/baseline.pkl'

    data = read_pickle(data_path)
    results = process_data(client, data, callee_key=args.callee_key)
    save_results(results, model_name)

if __name__ == "__main__":
    main()