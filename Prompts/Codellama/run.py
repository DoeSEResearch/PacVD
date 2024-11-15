import argparse
import logging
import os
import re
import pickle
import random
import json
import pandas as pd
from collections import namedtuple
import vllm
from prompts import PROMPT_FUNCTIONS  # Import prompt functions

# Define the CodeDocument data structure
CodeDocument = namedtuple(
    'CodeDocument',
    'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID API_summary API_sequence'
)

# Initialize logging
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Read a Pickle file
def read_pickle(file_path):
    """Reads a dataset from the specified pkl file and shuffles the contents."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The specified dataset file does not exist: {file_path}")

    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    random.shuffle(contents)
    return contents

# Process the dataset
def process_samples(model, samples, prompt_function):
    """Processes all samples using the selected prompt function."""
    results = []
    for index, code_document in enumerate(samples):
        logging.info(f"Processing document {index + 1}/{len(samples)}")

        # Generate prompt and log input
        prompt = prompt_function(code_document)
        logging.info(f"Model Input (Prompt): {prompt}")

        # Get prediction and model output
        prediction, model_output = get_prediction(model, prompt)
        logging.info(f"Model Output: {model_output}")

        # Determine prediction label
        prediction_label = 1 if prediction == "yes" else 0 if prediction == "no" else -1

        # Log prediction and original label
        logging.info(f"Original Label: {code_document.cls}, Predicted Label: {prediction_label}")

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

# Get prediction from the model
def get_prediction(model, prompt):
    """Generates a prediction from the model based on the given prompt."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            sampling_params = vllm.SamplingParams(temperature=0.1, top_p=0.95, max_tokens=512)
            outputs = model.generate([prompt], sampling_params)
            response = outputs[0].outputs[0].text.strip().lower()
            logging.info(f"Attempt {attempt + 1}, Model output: {response}")

            # Check if response contains "yes" or "no"
            if "yes" in response:
                return "yes", outputs[0].outputs[0].text.strip()
            elif "no" in response:
                return "no", outputs[0].outputs[0].text.strip()
        except Exception as e:
            logging.error(f"Error during model prediction (attempt {attempt + 1}): {str(e)}")
        logging.warning(f"Retrying... (attempt {attempt + 1})")
    return "error", "Model failed to provide a valid response."

# Save results
def save_results(results, prompt_type, dataset_name):
    """Saves the results in both JSON and Excel formats."""
    output_dir = '../../result'
    os.makedirs(output_dir, exist_ok=True)
    base_filename = f"codellama_{prompt_type}_{dataset_name}"

    # Save as JSON file
    json_file_path = os.path.join(output_dir, f'{base_filename}_results.json')
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')
    logging.info(f"Results saved to {json_file_path}")

    # Save as Excel file
    excel_file_path = os.path.join(output_dir, f'{base_filename}_results.xlsx')
    pd.DataFrame(results).to_excel(excel_file_path, index=False)
    logging.info(f"Results saved to {excel_file_path}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Vulnerability detection using CodeLlama model.")
    parser.add_argument('--data_file', required=True, help='Path to the dataset file (pkl format)')
    parser.add_argument('--prompt_type', required=True, choices=PROMPT_FUNCTIONS.keys(), help='Type of prompt to use')
    args = parser.parse_args()

    setup_logging()

    model_name = "codellama/CodeLlama-34b-Instruct-hf"  # Fixed model name
    model = vllm.LLM(model_name, download_dir="../../models")

    # Load dataset
    data_file_path = os.path.join('../../data', os.path.basename(args.data_file))
    logging.info(f"Loading dataset from {data_file_path}")
    selected_data = read_pickle(data_file_path)

    # Select the prompt function based on prompt_type
    prompt_function = PROMPT_FUNCTIONS[args.prompt_type]

    # Process samples and save results
    results = process_samples(model, selected_data, prompt_function)
    save_results(results, args.prompt_type, os.path.splitext(os.path.basename(args.data_file))[0])

if __name__ == "__main__":
    main()