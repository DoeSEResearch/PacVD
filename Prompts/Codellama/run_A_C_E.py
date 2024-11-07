import vllm
import pickle
import random
import collections
import json
import pandas as pd
import logging
import os
import re

# 设置代理
def setup_proxy():
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7900'
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7900'

# 初始化日志
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义 CodeDocument 结构
CodeDocument = collections.namedtuple(
    'CodeDocument',
    'words cls project CVE_ID CWE_ID commit parent_commit file_name '
    'file_ID function_ID API_summary API_sequence'
)

# 读取数据
def read_pickle(file_path, limit=None, shuffle=True):
    logging.info(f"Loading data from {file_path}")
    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    if shuffle:
        random.shuffle(contents)
    if limit and limit > 0:
        contents = random.sample(contents, limit)
    logging.info(f"Loaded {len(contents)} records from {file_path}")
    return contents

# 严格要求模型只回答 'yes' 或 'no' 的第一轮 Prompt
def format_prompt_round1(code_document):
    system_message = (
        "<s>[INST] <<SYS>>You are a vulnerability detection system. "
        "Please answer only with 'yes' or 'no'.<</SYS>>"
    )
    code_info = f"Code:\n{code_document.words}\nAPI Information: {code_document.API_sequence}\n"
    prompt = f"{system_message}\n\n{code_info}\nBased on the code and additional API information, does the code contain a vulnerability? Respond with 'yes' or 'no'. [/INST]"
    logging.info(f"Generated prompt for round 1: {prompt}")
    return prompt

# 第二轮 Prompt 提供漏洞依据和CWE类型
def format_prompt_round2(code_document):
    system_message = (
        "<s>[INST] <<SYS>> You have detected a vulnerability in the code. "
        "Now, your task is to provide a detailed reasoning for the vulnerability and identify its CWE type.<</SYS>>"
    )
    code_info = f"Code:\n{code_document.words}\nAPI Information: {code_document.API_sequence}\n"
    prompt = f"{system_message}\n\n{code_info}\n"
    logging.info(f"Generated prompt for round 2: {prompt}")
    return prompt

# 正则表达式检测 "yes" 或 "no"
def extract_yes_no(response):
    match = re.search(r'\b(yes|no)\b', response.strip().lower())
    return match.group(1) if match else None

# 使用正则表达式提取 CWE-XXX 格式
def extract_cwe_type(response):
    match = re.search(r'CWE-\d+', response.strip())
    return match.group(0) if match else None

# 获取模型预测，重试机制
def get_prediction(model, prompt, max_retries=3):
    for attempt in range(max_retries):
        try:
            sampling_params = vllm.SamplingParams(max_tokens=512, temperature=0.1)
            outputs = model.generate([prompt], sampling_params)
            response = outputs[0].outputs[0].text.strip()
            logging.info(f"Attempt {attempt + 1}, Model output: {response}")
            return response
        except Exception as e:
            logging.error(f"Error during model prediction (attempt {attempt + 1}): {str(e)}")
        logging.warning(f"Retrying... (attempt {attempt + 1})")
    return None

# 第一轮和第二轮的漏洞检测流程
def detect_vulnerability(model, code_document):
    # 第一轮：判断是否有漏洞，并重试三次
    for _ in range(3):
        prompt_round1 = format_prompt_round1(code_document)
        response_round1 = get_prediction(model, prompt_round1)
        judgment1 = extract_yes_no(response_round1)
        if judgment1 in ["yes", "no"]:
            break
    else:
        logging.error("Failed to get valid 'yes' or 'no' response after 3 attempts.")
        return {
            "judgment": "error",
            "basis": None,
            "cwe_type": None,
            "prediction_label": -1  # 表示错误
        }

    # 保存预测标签，yes为1，no为0
    prediction_label = 1 if judgment1 == "yes" else 0

    if judgment1 == "no":
        return {
            "judgment": "no",
            "basis": None,
            "cwe_type": None,
            "prediction_label": prediction_label
        }

    # 第二轮：如果有漏洞，判断依据和CWE类型，并重试三次
    for _ in range(3):
        prompt_round2 = format_prompt_round2(code_document)
        response_round2 = get_prediction(model, prompt_round2)
        basis = None
        cwe_type = extract_cwe_type(response_round2)

        if cwe_type:
            response_lines = response_round2.split("\n")
            for line in response_lines:
                if not extract_cwe_type(line):
                    basis = line.strip()  # 保留详细的漏洞判断信息
            break
    else:
        logging.error("Failed to get valid CWE type response after 3 attempts.")
        return {
            "judgment": "yes",
            "basis": "unknown",  # 无法获取详细判断依据
            "cwe_type": "unknown",
            "prediction_label": prediction_label
        }

    return {
        "judgment": "yes",
        "basis": basis,  # 保存漏洞判断的详细信息
        "cwe_type": cwe_type,
        "prediction_label": prediction_label
    }

# 处理样本并保存结果
def process_samples(model, samples):
    results = []
    for code_document in samples:
        model_output = detect_vulnerability(model, code_document)
        result_data = {
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
            # 保存模型输出，包括预测标签
            "judgment": model_output["judgment"],
            "basis": model_output["basis"],
            "cwe_type": model_output["cwe_type"],
            "prediction_label": model_output["prediction_label"]
        }
        logging.info(f"Processed file: {code_document.file_name}, Judgment: {model_output['judgment']}, Prediction Label: {model_output['prediction_label']}")
        results.append(result_data)
    return results

# 保存结果到JSON和Excel
def save_results(results, model_name, output_dir="../../result"):
    os.makedirs(output_dir, exist_ok=True)
    base_filename = model_name.replace("/", "_")
    json_file_path = os.path.join(output_dir, f'{base_filename}_API_CWE_CoT_answers.json')
    excel_file_path = os.path.join(output_dir, f'{base_filename}_API_CWE_CoT_answers.xlsx')

    # 保存到JSON
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')

    # 保存到Excel
    df = pd.DataFrame(results)
    df.to_excel(excel_file_path, index=False)

    logging.info(f"Results saved to {json_file_path} and {excel_file_path}")

# 主函数
def main():
    setup_proxy()
    setup_logging()

    model_name = "codellama/CodeLlama-34b-Instruct-hf"
    model = vllm.LLM(model_name, download_dir="../../models")

    bad_file_path = '../../src/combined_vul_files.pkl'
    good_file_path = '../../src/combined_non_vul_files.pkl'


    bad_samples = read_pickle(bad_file_path, shuffle=True)  # 打乱输入数据
    good_samples = read_pickle(good_file_path, shuffle=True)  # 打乱输入数据

    # 处理样本并获取结果
    results = process_samples(model, bad_samples + good_samples)

    # 保存结果到JSON和Excel
    save_results(results, model_name)


if __name__ == "__main__":
    main()
