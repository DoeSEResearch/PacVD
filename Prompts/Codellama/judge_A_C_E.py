import json
import re
import logging
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, matthews_corrcoef, confusion_matrix
from collections import Counter

# 配置日志设置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_cwe_type(cwe_str):
    """从CWE_type字符串中提取类似CWE-199的内容, 如果是 'unknown' 则返回 None"""
    if cwe_str and isinstance(cwe_str, str):
        match = re.search(r'CWE-\d+', cwe_str)
        if match:
            return match.group(0)
        elif 'unknown' in cwe_str.lower():
            return None
    return None

def evaluate_predictions(filename):
    targets = []
    preds = []
    normal_count = 0
    abnormal_count = 0
    cwe_target = []
    cwe_pred = []

    logging.info("开始评估模型预测结果...")

    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            obj = json.loads(line)
            target = 0 if obj['original_cls'] == 0 else 1
            prediction = obj.get('prediction_label', -1)  # 使用prediction_label字段

            original_cwe = obj.get('CWE_ID', None)
            predicted_cwe = extract_cwe_type(obj.get('cwe_type', ''))

            if prediction == -1:
                abnormal_count += 1
                continue

            normal_count += 1
            targets.append(target)
            preds.append(prediction)

            # 仅对模型预测为 'yes' 的样本进行CWE类型的评估
            if prediction == 1:  # 只在有漏洞的情况下评估CWE类型
                if original_cwe and predicted_cwe:
                    cwe_target.append(original_cwe)
                    cwe_pred.append(predicted_cwe)
                else:
                    logging.info(f"预测为'yes'但无法提取有效CWE: 原始CWE={original_cwe}, 预测CWE={predicted_cwe}")

    if len(preds) == 0:
        logging.error("未找到有效的预测结果。")
        return

    # 打印目标和预测的分布
    logging.info(f"目标分布 (标签): {Counter(targets)}")
    logging.info(f"预测分布 (模型判断): {Counter(preds)}")

    # 计算分类评估指标（整个样本集上的分类结果）
    acc = accuracy_score(targets, preds)
    recall = recall_score(targets, preds, average='binary')
    precision = precision_score(targets, preds, average='binary')
    f1 = f1_score(targets, preds, average='binary')
    mcc = matthews_corrcoef(targets, preds)

    logging.info("分类评估结果:")
    logging.info(f"准确率 (Accuracy): {acc:.4f}")
    logging.info(f"召回率 (Recall): {recall:.4f}")
    logging.info(f"精确率 (Precision): {precision:.4f}")
    logging.info(f"F1分数 (F1 Score): {f1:.4f}")
    logging.info(f"马修斯相关系数 (MCC): {mcc:.4f}")

    # 计算CWE判断的准确率，仅对预测为"yes"的样本
    if cwe_target and cwe_pred:
        cwe_acc = accuracy_score(cwe_target, cwe_pred)
        logging.info(f"CWE类型判断的准确率 (仅针对'yes'): {cwe_acc:.4f}")
    else:
        cwe_acc = None
        logging.warning("未找到足够的CWE数据进行评估。")

    logging.info(f"正常处理的样本数量: {normal_count}")
    logging.info(f"异常处理的样本数量: {abnormal_count}")

    result = {
        "eval_accuracy": float(acc),
        "eval_precision": float(precision),
        "eval_recall": float(recall),
        "eval_f1": float(f1),
        "eval_mcc": float(mcc),
        "normal_count": normal_count,
        "abnormal_count": abnormal_count,
        "cwe_accuracy": float(cwe_acc) if cwe_acc is not None else None  # 只计算有漏洞的CWE准确率
    }

    logging.info("最终评估结果:")
    logging.info(result)


if __name__ == '__main__':
    filename = '../../result/codellama_CodeLlama-34b-Instruct-hf_API_CWE_CoT_answers.json'
    evaluate_predictions(filename)
