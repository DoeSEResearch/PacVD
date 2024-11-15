import argparse
import logging
import os
import pickle
import random
import json
import pandas as pd
import collections
from openai import OpenAI
from prompts import PROMPT_FUNCTIONS

# Define the CodeDocument data structure
CodeDocument = collections.namedtuple(
    'CodeDocument',
    'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID API_summary API_sequence'
)


# Initialize logging
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Initialize the OpenAI client
def setup_openai_client(api_key):
    base_url = 'https://api.openai.com/v1'
    return OpenAI(base_url=base_url, api_key=api_key)


# Read a Pickle file
def read_pickle(file_path):
    """Reads a dataset from the specified pkl file and shuffles the contents"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The specified dataset file does not exist: {file_path}")

    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    random.shuffle(contents)  # Shuffle by default
    return contents


# Process the dataset
def process_data(client, data, prompt_type):
    results = []
    total_documents = len(data)
    prompt_function = PROMPT_FUNCTIONS[prompt_type]

    for index, code_document in enumerate(data):
        logging.info(f"Processing document {index + 1}/{total_documents}")
        prediction_output = prompt_function(client, code_document)

        if prediction_output is None:
            prediction_label = -1
            model_output = "Error: No response from model"
        else:
            prediction_label = 1 if "yes" in prediction_output.lower() else 0
            model_output = prediction_output.strip()

        # Log the model's output
        logging.info(f"Document {index + 1} model output: {model_output}")
        logging.info(f"Prediction label: {prediction_label}")

        results.append({
            "words": code_document.words,
            "cls": code_document.cls,
            "original_cls": code_document.cls,
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
            "prediction_label": prediction_label,
            "model_output": model_output
        })
    return results


# Save results
def save_results(results, prompt_type, dataset_name):
    output_dir = '../../result'  # Fixed output directory
    os.makedirs(output_dir, exist_ok=True)
    base_filename = f"gpt-4o_{prompt_type}_{dataset_name}"

    # Save as JSON file
    json_file_path = os.path.join(output_dir, f'{base_filename}.json')
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')  # Store each JSON object on a new line
    logging.info(f"Results saved to {json_file_path}")

    # Save as Excel file
    excel_file_path = os.path.join(output_dir, f'{base_filename}.xlsx')
    pd.DataFrame(results).to_excel(excel_file_path, index=False)
    logging.info(f"Results saved to {excel_file_path}")


# Main function
def main():
    parser = argparse.ArgumentParser(description="Vulnerability detection using OpenAI GPT-4o model.")
    parser.add_argument('--api_key', required=True, help='OpenAI API key')
    parser.add_argument('--data_file', required=True,
                        help='Path to the dataset file (pkl format, e.g., A1.pkl, baseline.pkl, basic.pkl)')
    parser.add_argument('--prompt_type', required=True, choices=PROMPT_FUNCTIONS.keys(), help='Type of prompt to use')
    args = parser.parse_args()

    setup_logging()
    client = setup_openai_client(args.api_key)

    # Extract dataset name from the file path
    dataset_name = os.path.splitext(os.path.basename(args.data_file))[0]

    # Load dataset
    data_file_path = os.path.join('../../data', os.path.basename(args.data_file))
    logging.info(f"Loading dataset from {data_file_path}")
    selected_data = read_pickle(data_file_path)

    # Process the data and save the results
    results = process_data(client, selected_data, args.prompt_type)
    save_results(results, args.prompt_type, dataset_name)


if __name__ == "__main__":
    main()