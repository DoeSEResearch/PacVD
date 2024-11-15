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

# Initialize logging for the script
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Setup DeepSeek API client
def setup_deepseek_client(api_key):
    return OpenAI(api_key=api_key, base_url='https://api.deepseek.com')

# Read data from a pickle file
def read_pickle(file_path, limit=None, shuffle=True):
    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    if limit:
        contents = random.sample(contents, limit)
    if shuffle:
        random.shuffle(contents)
    return contents

# Initialize conversation context for vulnerability detection
def initialize_conversation():
    return [{"role": "system", "content": "You are a professional code reviewer."}]

# Generate prompt context based on round number
def format_prompt(code_document, round_num=1, code_analysis=None):
    if round_num == 1:
        context = (
            "Analyze the code snippet for clarity, functionality, and resource management practices. "
            "Use the API information to understand code structure, identify all resource allocations, and verify if they are properly managed."
        )
        prompt = (
            f"{initialize_conversation()[0]['content']}\n\n{context}\n\n"
            f"Code Snippet:\n{code_document.words}\n\nAPI Information:\n{code_document.API_sequence}"
        )
    elif round_num == 2 and code_analysis is not None:
        context = (
            f"Based on the analysis result: '{code_analysis}', make a final determination on whether improvements are needed "
            "in the code's resource management and clarity. Answer 'yes' if any improvements are recommended, or 'no' if the code meets all criteria."
        )
        prompt = f"{initialize_conversation()[0]['content']}\n\n{context}"
    else:
        raise ValueError("Second round prompt requires valid code_analysis from the first round.")

    logging.info(f"Generated prompt (round {round_num}): {prompt}")
    return prompt

# Multi-round model prediction
def get_prediction(model, prompt):
    response = model.chat.completions.create(
        model="deepseek-coder",
        messages=[{"role": "user", "content": prompt}],
        stream=False
    )
    response_content = response.choices[0].message.content.strip()
    return response_content, response

# Detect vulnerability in a code document
def detect_vulnerability(model, code_document, doc_index, callee_key="whole_callees"):
    logging.info(f"Processing document {doc_index + 1}")

    # Ensure API_sequence uses specified callee_key
    if callee_key in code_document.API_sequence:
        code_document = code_document._replace(API_sequence=code_document.API_sequence[callee_key])
    else:
        logging.warning(f"{callee_key} not found in API_sequence. Using default empty value.")
        code_document = code_document._replace(API_sequence="")

    conversation_history = initialize_conversation()

    # First step: analyze the code
    prompt_round_1 = format_prompt(code_document, round_num=1)
    response_round_1, _ = get_prediction(model, prompt_round_1)
    logging.info(f"Round 1 - Model Output: {response_round_1}")

    conversation_history.append({"role": "user", "content": prompt_round_1})
    conversation_history.append({"role": "assistant", "content": response_round_1})

    # Second step: make a final determination based on analysis
    code_analysis = response_round_1
    prompt_round_2 = format_prompt(code_document, round_num=2, code_analysis=code_analysis)
    response_round_2, _ = get_prediction(model, prompt_round_2)
    logging.info(f"Round 2 - Model Output: {response_round_2}")

    # Determine the final prediction label
    prediction_label = 1 if "yes" in response_round_2.lower() else 0 if "no" in response_round_2.lower() else -1

    logging.info(f"Document {doc_index + 1} - Original Label: {code_document.cls}, Predicted Label: {prediction_label}")
    return prediction_label, code_document.cls, response_round_2

# Process data for vulnerability detection
def process_data(client, data, callee_key):
    results = []
    for i, code_document in enumerate(data):
        prediction, original_label, prediction_output = detect_vulnerability(client, code_document, i, callee_key)
        results.append({
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
        })
    return results

# Save results
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
    parser = argparse.ArgumentParser(description="Vulnerability detection using DeepSeek baseline.")
    parser.add_argument('--api_key', required=True, help='API key for DeepSeek or OpenAI')
    parser.add_argument('--callee_key', required=True, choices=[
        'All', 'API_sample', 'hierarchy_sample', 'Random_sample', 'similar_sample'
    ], help='Callee key type')
    args = parser.parse_args()

    setup_logging()
    client = setup_deepseek_client(api_key=args.api_key)

    data_path = '../../data/baseline.pkl'
    data = read_pickle(data_path)
    results = process_data(client, data, args.callee_key)
    save_results(results, "deepseek-coder")

if __name__ == "__main__":
    main()