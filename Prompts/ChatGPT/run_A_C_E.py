from openai import OpenAI
import logging
import os
import pickle
import random
import pandas as pd
import collections
import json
import re

# Define CodeDocument structure
CodeDocument = collections.namedtuple(
    'CodeDocument',
    'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID API_summary API_sequence'
)

# Set proxy
def setup_proxy():
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7900'
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7900'

# Initialize logging
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set up OpenAI API client
def setup_openai_client():
    return OpenAI(
        base_url='https://xiaoai.plus/v1',
        api_key=''  # Use your OpenAI API key
    )

# Read pickle file
def read_pickle(file_path, limit=None, shuffle=True):
    with open(file_path, "rb") as f:
        contents = pickle.load(f)

    if shuffle:
        random.shuffle(contents)

    if limit is not None:
        contents = contents[:limit]

    return contents

# Extract CWE type from model output
def extract_cwe_type(output):
    match = re.search(r'CWE-\d+', output)
    return match.group(0) if match else None

# Get prediction from ChatGPT-4o model
def get_prediction(client, code_document):
    messages = []
    # Step 1: Determine the intention of the code
    prompt_intention = (
        "Analyze the following code snippet and provide a detailed description of its purpose and functionality. "
        f"\n\nCode Snippet:\n{code_document.words}"
        f"\n\nAPI Information:\n{code_document.API_sequence}"
    )

    messages.append({"role": "system", "content": "You are a specialized assistant in software code analysis."})
    messages.append({"role": "user", "content": prompt_intention})

    logging.info(f"Sending intention prompt to model:\n{prompt_intention}")

    try:
        response_intention = client.chat.completions.create(
            model="gpt-4o",
            messages=messages
        )
        intention_output = response_intention.choices[0].message.content.strip()
        logging.info(f"Parsed intention output: {intention_output}")
    except Exception as e:
        logging.error(f"Error during intention prediction: {str(e)}")
        return -1, None, None, None

    # Step 2: Determine if there is a vulnerability based on the code's intention
    prompt_vulnerability = (
        "Based on the following code snippet and its intention, determine if there is any potential security vulnerability. "
        "If the code is vulnerable, start your answer with 'yes' followed by reasoning. If the code is not vulnerable, start your answer with 'no' followed by reasoning. "
        f"\n\nCode Snippet:\n{code_document.words}"
        f"\n\nIntention:\n{intention_output}"
    )

    messages.append({"role": "user", "content": prompt_vulnerability})
    logging.info(f"Sending vulnerability prompt to model:\n{prompt_vulnerability}")

    try:
        response_vulnerability = client.chat.completions.create(
            model="gpt-4o",
            messages=messages
        )
        vulnerability_output = response_vulnerability.choices[0].message.content.strip()
        logging.info(f"Parsed vulnerability output: {vulnerability_output}")

        if "yes" in vulnerability_output.lower():
            # Step 3: Determine CWE type and provide reasoning
            prompt_cwe = (
                "Based on the following vulnerability analysis, provide the CWE type and a detailed explanation. "
                f"\n\nVulnerability Analysis:\n{vulnerability_output}"
            )

            messages.append({"role": "user", "content": prompt_cwe})
            logging.info(f"Sending CWE prompt to model:\n{prompt_cwe}")

            try:
                response_cwe = client.chat.completions.create(
                    model="gpt-4o",
                    messages=messages
                )
                cwe_output = response_cwe.choices[0].message.content.strip()
                logging.info(f"Parsed CWE output: {cwe_output}")
                cwe_type = extract_cwe_type(cwe_output)
                basis = cwe_output  # Store the entire CWE analysis as the reasoning
                logging.info(f"Extracted CWE Type: {cwe_type}, Reasoning: {basis}")
                return 1, vulnerability_output, cwe_type, basis  # 1 indicates vulnerability found
            except Exception as e:
                logging.error(f"Error during CWE prediction: {str(e)}")
                return 1, vulnerability_output, None, vulnerability_output  # Store reasoning even if CWE extraction fails
        elif "no" in vulnerability_output.lower():
            basis = vulnerability_output  # Store the entire output as the reasoning
            logging.info(f"Reasoning: {basis}")
            return 0, vulnerability_output, None, basis  # 0 indicates no vulnerability
    except Exception as e:
        logging.error(f"Error during vulnerability prediction: {str(e)}")

    return -1, None, None, None  # -1 indicates the model could not provide a valid prediction

# Detect vulnerability
def detect_vulnerability(client, code_document, index, total_documents):
    logging.info(f"Processing document {index + 1}/{total_documents}")
    prediction, model_output, cwe_type, basis = get_prediction(client, code_document)
    original_cls = 0 if code_document.cls == 0 else 1
    logging.info(f"Original label: {original_cls}, Prediction: {prediction}, Model output: {model_output}, CWE Type: {cwe_type}, Basis: {basis}")
    return prediction, original_cls, model_output, cwe_type, basis

# Process dataset
def process_data(client, data):
    results = []
    total_documents = len(data)
    for index, code_document in enumerate(data):
        prediction, original_label, prediction_output, cwe_type, basis = detect_vulnerability(client, code_document, index, total_documents)
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
            "model_output": prediction_output,
            "cwe_type": cwe_type,
            "reasoning": basis
        })
    return results

# Save results to JSON and Excel
def save_results(results, model_name, output_dir="../../result"):
    os.makedirs(output_dir, exist_ok=True)
    base_filename = model_name.replace("/", "_")

    # Save to JSON file
    json_file_path = os.path.join(output_dir, f'{base_filename}_API_CoT_CWE_answers.json')
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')

    # Save to Excel file
    excel_file_path = os.path.join(output_dir, f'{base_filename}_API_CoT_CWE_answers.xlsx')
    pd.DataFrame(results).to_excel(excel_file_path, index=False)

    logging.info(f"Results saved to {json_file_path} and {excel_file_path}")

# Main function
def main():
    setup_proxy()
    setup_logging()
    client = setup_openai_client()

    model_name = "gpt-4o"

    bad_file_path = '../../src/combined_vul_files.pkl'
    good_file_path = '../../src/combined_non_vul_files.pkl'

    logging.info(f"Loading bad samples.")
    bad_samples = read_pickle(bad_file_path, limit=20, shuffle=True)  # Set limit=20 to load 20 samples
    logging.info(f"Loading good samples.")
    good_samples = read_pickle(good_file_path, limit=20, shuffle=True)  # Set limit=20 to load 20 samples

    all_data = bad_samples + good_samples
    random.shuffle(all_data)

    results = process_data(client, all_data)
    save_results(results, model_name)

if __name__ == "__main__":
    main()
