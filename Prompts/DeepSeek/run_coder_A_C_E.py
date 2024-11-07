import re
from openai import OpenAI
import logging
import os
import pickle
import random
import pandas as pd
import collections
import json

# 定义 CodeDocument 结构
CodeDocument = collections.namedtuple(
    'CodeDocument',
    'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID API_summary API_sequence'
)

# 设置代理
def setup_proxy():
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7900'
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7900'

# 初始化日志
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    return logger

# 设置 DeepSeek API 客户端
def setup_deepseek_client():
    client = OpenAI(
        api_key="",  # 替换为你的实际API密钥
        base_url="https://api.deepseek.com/beta"
    )
    return client

# 读取 pickle 文件
def read_pickle(file_path, limit=None, shuffle=True):
    with open(file_path, "rb") as f:
        contents = pickle.load(f)
    if limit is not None:
        contents = random.sample(contents, limit)
    if shuffle:
        random.shuffle(contents)
    return contents

# 初始化对话上下文
def initialize_conversation():
    return [
        {
            "role": "system",
            "content": "You are an expert vulnerability detection system. Provide precise and direct answers with explanations only when necessary."
        }
    ]

# 重试逻辑函数
def retry_request(client, conversation_history, prompt, max_retries=3, extract_func=None, logger=None):
    for attempt in range(max_retries):
        logger.info(f"Attempt {attempt + 1}: Sending prompt to model: {prompt}")
        conversation_history.append({
            "role": "user",
            "content": prompt
        })
        response = client.chat.completions.create(
            model="deepseek-coder",
            messages=conversation_history
        )
        logger.info(f"Model response received: {response.choices[0].message.content}")
        conversation_history.append({"role": "assistant", "content": response.choices[0].message.content})
        output = response.choices[0].message.content.strip().lower()

        if extract_func:
            extracted = extract_func(output)
            if extracted:
                logger.info(f"Extracted valid result: {extracted}")
                return extracted, conversation_history  # 提取成功后，立即返回结果并停止重试
        else:
            logger.warning(f"Invalid response, retrying...")

    logger.error("Failed to retrieve a valid response after max retries.")
    return None, conversation_history

# 提取yes/no的正则匹配
def extract_yes_no(output):
    match = re.search(r'\b(yes|no)\b', output)
    return match.group(1) if match else None

# 提取CWE类型和判断依据的正则匹配
def extract_cwe_and_reasoning(output):
    cwe_match = re.search(r'\bCWE-(\d+)', output, re.IGNORECASE)  # 忽略大小写匹配
    if cwe_match:
        cwe_type = f"CWE-{cwe_match.group(1).upper()}"
    else:
        logging.warning(f"Unable to extract CWE from output: {output}")
        cwe_type = None

    # 提取漏洞判断依据，即CWE编号后的详细描述
    reasoning = output.split(cwe_match.group(0), 1)[-1].strip() if cwe_match else None
    return cwe_type, reasoning

def get_multi_round_prediction(client, code_document, conversation_history, logger):
    # 第1轮：结合API信息分析代码是否有漏洞
    prompt_1 = f"Code:\n{code_document.words}\nAPI Information: {code_document.API_sequence}\nBased on the code and API Information , does the code contain a vulnerability? Respond with 'yes' or 'no'. "
    logger.info(f"Starting vulnerability detection for: {code_document.file_name}")
    result, conversation_history = retry_request(client, conversation_history, prompt_1, extract_func=extract_yes_no, logger=logger)

    if not result or result == "no":
        logger.info(f"No vulnerability detected for file: {code_document.file_name}")
        return result, None, None, conversation_history

    # 第2轮：如果有漏洞，分析漏洞的原因和CWE类型
    prompt_2 = "What is the specific vulnerability in the code? Please provide the corresponding CWE number in the format 'CWE-XXX', and explain the reasoning behind this vulnerability."
    cwe_type_and_reasoning, conversation_history = retry_request(client, conversation_history, prompt_2, extract_func=extract_cwe_and_reasoning, logger=logger)

    if cwe_type_and_reasoning:
        cwe_type, reasoning = cwe_type_and_reasoning  # 解包CWE类型和判断依据
        logger.info(f"Vulnerability detected with CWE: {cwe_type} and reasoning: {reasoning}")
        return result, cwe_type, reasoning, conversation_history  # 成功提取后返回
    else:
        logger.warning(f"No CWE type detected for file: {code_document.file_name}")

    return result, None, None, conversation_history


# 检测漏洞
def detect_vulnerability(client, code_document, logger):
    conversation_history = initialize_conversation()
    prediction, cwe_type, reasoning, conversation_history = get_multi_round_prediction(client, code_document,
                                                                                       conversation_history, logger)

    original_cls = 0 if code_document.cls == 0 else 1  # 原始标签，0表示无漏洞，1表示有漏洞
    prediction_label = 1 if prediction == "yes" else 0  # 增加预测标签
    logger.info(
        f"Detection complete for file: {code_document.file_name}, Prediction: {prediction}, Original Class: {original_cls}, Prediction Label: {prediction_label}, CWE Type: {cwe_type}, Reasoning: {reasoning}")

    return prediction, original_cls, cwe_type, reasoning, prediction_label


# 处理数据集
def process_data(client, data, logger):
    results = []
    for code_document in data:
        logger.info(f"Processing code document: {code_document.file_name}")
        prediction, original_label, cwe_type, reasoning, prediction_label = detect_vulnerability(client, code_document, logger)

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
            "prediction": prediction,  # 最终判断结果
            "cwe_type": cwe_type,  # CWE类型
            "reasoning": reasoning,  # 漏洞判断依据
            "prediction_label": prediction_label  # 增加预测标签 (1: 有漏洞, 0: 无漏洞)
        }
        results.append(result_data)
        logger.info(f"Results for file {code_document.file_name} added to results list.")
    return results


# 保存结果到 JSON 和 Excel
def save_results(results, model_name, output_dir="../../result", logger=None):
    os.makedirs(output_dir, exist_ok=True)
    base_filename = model_name.replace("/", "_")

    # 保存到 JSON 文件
    json_file_path = os.path.join(output_dir, f'{base_filename}_API_CoT_CWE_answers.json')
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        for result in results:
            json.dump(result, json_file)
            json_file.write('\n')
    logger.info(f"Results saved to JSON: {json_file_path}")

    # 保存到 Excel 文件
    excel_file_path = os.path.join(output_dir, f'{base_filename}_API_CoT_CWE_answers.xlsx')
    df = pd.DataFrame(results)
    df.to_excel(excel_file_path, index=False)
    logger.info(f"Results saved to Excel: {excel_file_path}")


# 主函数
def main():
    setup_proxy()
    logger = setup_logging()
    client = setup_deepseek_client()

    model_name = "deepseek-coder"

    # 读取有漏洞和无漏洞的数据集
    bad_file_path = '../../src/combined_vul_files.pkl'
    good_file_path = '../../src/combined_non_vul_files.pkl'

    bad_data = read_pickle(bad_file_path, shuffle=True)
    good_data = read_pickle(good_file_path, shuffle=True)

    all_data = bad_data + good_data
    random.shuffle(all_data)

    logger.info(f"Data loaded successfully. Total files to process: {len(all_data)}")

    results = process_data(client, all_data, logger)

    save_results(results, model_name, logger=logger)

if __name__ == "__main__":
    main()
