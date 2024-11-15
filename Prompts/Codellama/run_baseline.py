import argparse
import logging
import os
import pickle
import random
import json
import pandas as pd
from collections import namedtuple
import vllm

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
    """Reads a dataset from the specified pkl file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The specified dataset file does not exist: {file_path}")

    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    random.shuffle(contents)
    return contents


# Generate the prompt
def generate_prompt(code_document, callee_key):
    api_info = code_document.API_sequence.get(callee_key, "No API information available for this key.")

    prompt = (
        "You are an AI assistant specialized in detecting security vulnerabilities in code. "
        "\n\nExamples:"
        "\n\nCode Snippet 1:\n"
        "Code:\nint jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n{\n    return (tsfb->numlvls > 0 && jas_seq2d_size(a)) ?\n      jpc_tsfb_synthesize2(tsfb,\n      jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),\n      jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),\n      jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;\n}\n"
        "API Information:\nIn the function jpc_tsfb_synthesize2, no branches allocate memory.\nIn the function jpc_tsfb_synthesize2, memory is not released on any branches.\nOutput: no"
        "\n\nCode Snippet 2:\n"
        "Code:\nstatic void read_const_block_data(ALSDecContext *ctx, ALSBlockData *bd)\n{\n    ALSSpecificConfig *sconf = &ctx->sconf;\n    AVCodecContext *avctx    = ctx->avctx;\n    GetBitContext *gb        = &ctx->gb;\n\n    *bd->raw_samples = 0;\n    *bd->const_block = get_bits1(gb);    // 1 = constant value, 0 = zero block (silence)\n    bd->js_blocks    = get_bits1(gb);\n\n    // skip 5 reserved bits\n    skip_bits(gb, 5);\n\n    if (*bd->const_block) {\n        unsigned int const_val_bits = sconf->floating ? 24 : avctx->bits_per_raw_sample;\n        *bd->raw_samples = get_sbits_long(gb, const_val_bits);\n    }\n\n    // ensure constant block decoding by reusing this field\n    *bd->const_block = 1;\n}\n"
        "API Information:\nIn the function skip_bits, no branches allocate memory.\nIn the function skip_bits, memory is not released on any branches.\nIn the function get_sbits_long, no branches allocate memory.\nIn the function get_sbits_long, memory is not released on any branches.\nIn the function get_bits1, no branches allocate memory.\nIn the function get_bits1, memory is not released on any branches.\nOutput: yes"
        "\nRefer to above examples, Analyze the following code snippet and associated API information. Provide a detailed response on whether the code is vulnerable. "
        "If the code is vulnerable, start your answer with 'yes' followed by a brief explanation. If the code is not vulnerable, start your answer with 'no' followed by reasoning."
        f"\n\nCode Snippet:\nCode:\n{code_document.words}"
        f"\nAPI Information:\n{api_info}"
    )
    logging.info(f"Generated prompt: {prompt}")
    return prompt


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

            if "yes" in response:
                return "yes", outputs[0].outputs[0].text.strip()
            elif "no" in response:
                return "no", outputs[0].outputs[0].text.strip()
        except Exception as e:
            logging.error(f"Error during model prediction (attempt {attempt + 1}): {str(e)}")
        logging.warning(f"Retrying... (attempt {attempt + 1})")
    return "error", "Model failed to provide a valid response."


# Process the dataset
def process_samples(model, samples, callee_key):
    results = []
    for index, code_document in enumerate(samples):
        logging.info(f"Processing document {index + 1}/{len(samples)}")

        prompt = generate_prompt(code_document, callee_key)
        prediction, model_output = get_prediction(model, prompt)
        prediction_label = 1 if prediction == "yes" else 0 if prediction == "no" else -1

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


# Save results
def save_results(results, callee_key):
    output_dir = '../../result'
    os.makedirs(output_dir, exist_ok=True)
    base_filename = f"codellama_{callee_key}_baseline"

    json_file_path = os.path.join(output_dir, f'{base_filename}_results.json')
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')
    logging.info(f"Results saved to {json_file_path}")

    excel_file_path = os.path.join(output_dir, f'{base_filename}_results.xlsx')
    pd.DataFrame(results).to_excel(excel_file_path, index=False)
    logging.info(f"Results saved to {excel_file_path}")


# Main function
def main():
    parser = argparse.ArgumentParser(description="Vulnerability detection using CodeLlama model.")
    parser.add_argument('--callee_key', required=True, choices=[
        'All', 'API_sample', 'hierarchy_sample', 'Random_sample', 'similar_sample'
    ], help='Callee key type')
    args = parser.parse_args()

    setup_logging()

    model_name = "codellama/CodeLlama-34b-Instruct-hf"
    model = vllm.LLM(model_name, download_dir="../../models")

    data_file_path = '../../data/baseline.pkl'
    logging.info(f"Loading dataset from {data_file_path}")
    selected_data = read_pickle(data_file_path)

    results = process_samples(model, selected_data, args.callee_key)
    save_results(results, args.callee_key)


if __name__ == "__main__":
    main()