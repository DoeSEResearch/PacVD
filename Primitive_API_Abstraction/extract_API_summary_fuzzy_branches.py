import concurrent
import gc
import os
import signal
import time

import networkx as nx
import re
import collections
import pickle
import argparse
from joblib import Parallel, delayed
from extract_NVD import read_pkl
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import logging
import logging.handlers
import multiprocessing
import sys
import psutil
from collections import deque

CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID API_summary API_sequence')

logger = logging.getLogger()
max_task_timeout = 2000

# 设定内存使用的上下限阈值
MEMORY_UPPER_THRESHOLD = 70  # 当内存使用超过 70% 时停止提交新任务
MEMORY_LOWER_THRESHOLD = 50  # 当内存使用低于 50% 时允许提交新任务

# 定义所有 CWE 对应的 API 列表
all_proven_all_CWE_APIs = {
    # Memory Leak
    "CWE-401": ["malloc", "calloc", "realloc", "free"],
    # "CWE-401": ["malloc", "free"],
    # Double Free
    "CWE-415": ["malloc", "calloc", "realloc", "free"],
    # "CWE-415": ["malloc", "free"],
    # Use After Free
    "CWE-416": ["malloc", "calloc", "realloc", "free"],
    # "CWE-416": ["malloc", "free"],
    # NULL Pointer Dereference
    "CWE-476": ["malloc", "calloc", "realloc", "free", "localtime"],
    # Resource Leak
    # Improper Resource Shutdown or Release
    "CWE-404": ["open", "fopen", "fdopen", "opendir", "close", "fclose", "closedir",
                "socket","shutdown","endmntent", "fflush",  "malloc", "calloc", "realloc", "free"],

    # Missing Release of Resource after Effective Lifetime
    # "CWE-772": ["open", "fopen", "fdopen", "opendir", "close", "fclose", "closedir"],
    "CWE-772": ["open", "socket", "fopen", "fdopen", "opendir", "close", "fclose", "endmntent", "fflush", "closedir",
                "shutdown", "malloc", "calloc", "realloc", "free"],
    # Incomplete Cleanup
    # "CWE-459": ["open", "fopen", "fdopen", "opendir", "close", "fclose", "closedir"],
    "CWE-459": ["open", "socket", "fopen", "fdopen", "opendir", "close", "fclose", "endmntent", "fflush", "closedir",
                "shutdown", "malloc", "calloc", "realloc", "free"],
    # Missing Release of File Descriptor or Handle after Effective Lifetime
    # "CWE-775": ["open", "fopen", "fdopen", "opendir", "close", "fclose", "closedir"],
    "CWE-775":  ["open", "socket", "fopen", "fdopen", "opendir", "close", "fclose", "endmntent", "fflush", "closedir",
            "shutdown", "malloc", "calloc", "realloc", "free"],
    # Improper Control of a Resource Through its Lifetime
    # "CWE-664": ["open", "fopen", "fdopen", "opendir", "close", "fclose", "closedir"],
    "CWE-664": ["open", "socket", "fopen", "fdopen", "opendir", "close", "fclose", "endmntent", "fflush", "closedir",
            "shutdown", "malloc", "calloc", "realloc", "free"],
    # Missing Reference to Active Allocated Resource
    # "CWE-771": ["open", "fopen", "fdopen", "opendir", "close", "fclose", "closedir"]
    "CWE-771": ["open", "socket", "fopen", "fdopen", "opendir", "close", "fclose", "endmntent", "fflush", "closedir",
            "shutdown", "malloc", "calloc", "realloc", "free"]
}
proven_all_CWE = list(all_proven_all_CWE_APIs.keys())


# 定义内存监控函数
def check_memory_threshold():
    """
    检查当前内存使用情况
    :return: 'add' 表示可以提交新任务，'stop' 表示暂停提交新任务
    """
    mem = psutil.virtual_memory()
    if mem.percent < MEMORY_LOWER_THRESHOLD:
        return 'add'
    elif mem.percent > MEMORY_UPPER_THRESHOLD:
        return 'stop'
    else:
        return 'normal'


# 定义超时信号处理器
def handler(signum, frame):
    raise TimeoutError("Subprocess timed out!")

def setup_logging(save_dir, log_file_name):
    log_queue = multiprocessing.Queue()
    queue_handler = logging.handlers.QueueHandler(log_queue)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(queue_handler)

    # Define handlers for the listener
    log_file_path = os.path.join(save_dir, log_file_name)
    file_handler = logging.FileHandler(log_file_path)
    stream_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    # Create a QueueListener
    listener = logging.handlers.QueueListener(log_queue, file_handler, stream_handler)
    listener.start()

    return listener

def find_function_node(graph, function_name, file_name):
    for node in graph.nodes(data=True):
        if node[1].get('label') and node[1].get('NAME') and node[1].get('FILENAME'):
            if node[1]['label'] == 'METHOD' and function_name in node[1]['NAME'] and file_name in node[1]['FILENAME']:
                return node
    return None

def find_call_nodes(dot_data, function_id):
    call_nodes = set()
    successors = list(dot_data.successors(function_id))
    for successor in successors:
        if 'label' in dot_data.nodes[successor] and 'CALL' in dot_data.nodes[successor]['label']:
            for src, dest, edge_data in dot_data.edges(successor, data=True):
                if 'label' in edge_data and edge_data['label'] == 'CALL' and '{' in dot_data.nodes[dest].get('CODE', ''):
                    call_nodes.add(dest)
    return call_nodes


def parse_dot_for_calls_and_cfgs_all(dot_file_path):
    # graph = nx.MultiDiGraph()  # Use MultiDiGraph to allow multiple edges between nodes
    graph = nx.DiGraph()
    with open(dot_file_path, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Skip empty lines or comments
        if not line or line.startswith('//'):
            i += 1
            continue

        # Handle node definitions
        if '[' in line and '->' not in line:
            # Node definition may span multiple lines
            node_lines = [line]
            while not line.endswith(']') and i + 1 < len(lines):
                i += 1
                line = lines[i].strip()
                node_lines.append(line)
            node_def = ' '.join(node_lines)
            node_match = re.match(r'(\w+)\s*\[(.*)\]', node_def, re.DOTALL)
            if node_match:
                node_id = node_match.group(1)
                attr_text = node_match.group(2)
                attributes = parse_attributes(attr_text)
                # Only keep nodes with label=METHOD or label=CALL
                node_label = attributes.get('label', '')
                if node_label in ['METHOD', 'CALL', 'CONTROL_STRUCTURE']:
                    graph.add_node(node_id, **attributes)
            i += 1
            continue

        # Handle edge definitions
        elif '->' in line:
            # Edge definition may span multiple lines
            edge_lines = [line]
            while not line.endswith(']') and i + 1 < len(lines):
                i += 1
                line = lines[i].strip()
                edge_lines.append(line)
            edge_def = ' '.join(edge_lines)
            edge_match = re.match(r'(\w+)\s*->\s*(\w+)\s*\[(.*)\]', edge_def, re.DOTALL)
            if edge_match:
                src = edge_match.group(1)
                dst = edge_match.group(2)
                attr_text = edge_match.group(3)
                attributes = parse_attributes(attr_text)
                edge_label = attributes.get('label', '')
                # if edge_label in ['CALL', 'CFG', 'CONTAINS', 'AST']:
                if edge_label in ['CALL', 'CFG', 'CONTAINS']:
                    # Add edge with unique key to avoid overwriting
                    edge_key = len(graph.get_edge_data(src, dst, default={}))
                    graph.add_edge(src, dst, key=edge_key, **attributes)
            i += 1
            continue

        else:
            i += 1

    return graph


def parse_attributes(label_data):
    """
    解析 DOT 文件中节点和边的属性。
    """
    attributes = {}
    pattern = r'(\w+)=(".*?(?<!\\)"|\S+)'
    matches = re.findall(pattern, label_data, re.DOTALL)
    for key, value in matches:
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        attributes[key] = value
    return attributes


def find_branches(dot_data, function_node_id, proven_all_CWE_API):
    branches = []
    cfg_edges = []
    for src, dst, edge_data in dot_data.edges(data=True):
        if 'label' in edge_data:
            if 'CFG' in edge_data['label']:
                cfg_edges.append((src, dst))
        else:
            cfg_edges.append((src, dst))

    cfg_successors = {}
    for src, dst in cfg_edges:
        cfg_successors.setdefault(src, []).append(dst)

    def dfs(current_node, current_path, current_calls, current_conditions, visited):
        current_path = current_path + [current_node]
        node_data = dot_data.nodes[current_node]
        code_content = node_data.get('CODE', '').lower() if 'CODE' in node_data else ''

        # 检查节点是否为条件结构
        conditions = current_conditions.copy()
        if node_data.get('label') == 'CONTROL_STRUCTURE':
            conditions.append(code_content.strip())

        # 检查API调用
        calls_in_node = []
        for api in proven_all_CWE_API:
            pattern = r'\b' + re.escape(api.lower()) + r'\s*\('
            if re.search(pattern, code_content):
                calls_in_node.append(api)

        current_calls = current_calls + calls_in_node
        successors = cfg_successors.get(current_node, [])
        visited = visited.union({current_node})

        if not successors:
            branches.append({
                'id': current_path,
                'calls': current_calls,
                'conditions': conditions
            })
        else:
            for successor in successors:
                if successor not in visited:
                    dfs(successor, current_path, current_calls.copy(), conditions.copy(), visited)
                else:
                    pass
        gc.collect()
    dfs(function_node_id, [], [], [], set())
    return branches


def analyze_callee_memory_usage(dot_data, callee_function_node_id, proven_all_CWE_API, depth, max_depth):
    summary = {
        'function_name': '',
        'api_in_some_branches': {api: False for api in proven_all_CWE_API},
        'api_in_all_branches': {api: True for api in proven_all_CWE_API},
        'branch_analysis': [],
        'callees': []
    }

    if depth > max_depth:
        return summary
    if callee_function_node_id not in dot_data.nodes:
        return summary

    node_data = dot_data.nodes[callee_function_node_id]
    summary['function_name'] = node_data.get('NAME', '').strip('""')

    callee_call_nodes = find_call_nodes(dot_data, callee_function_node_id)

    for callee_call_node in callee_call_nodes:
        if callee_call_node not in dot_data.nodes:
            continue

        deeper_summary = analyze_callee_memory_usage(dot_data, callee_call_node, proven_all_CWE_API, depth + 1, max_depth)
        summary['callees'].append(deeper_summary)
        for api in proven_all_CWE_API:
            summary['api_in_some_branches'][api] = summary['api_in_some_branches'][api] or deeper_summary['api_in_some_branches'][api]
            summary['api_in_all_branches'][api] = summary['api_in_all_branches'][api] and deeper_summary['api_in_all_branches'][api]

    branches = find_branches(dot_data, callee_function_node_id, proven_all_CWE_API)
    for branch in branches:
        for api in proven_all_CWE_API:
            api_in_branch = api in branch['calls']
            summary['api_in_some_branches'][api] = summary['api_in_some_branches'][api] or api_in_branch
            summary['api_in_all_branches'][api] = summary['api_in_all_branches'][api] and api_in_branch

        summary['branch_analysis'].append(branch)
    gc.collect()
    return summary


def summarize_memory_usage(memory_summary, node_data, proven_all_CWE_API):
    function_name = memory_summary.get('function_name', node_data.get('NAME', '').strip('""'))
    summaries = []

    # 收集API调用的条件
    api_conditions = {api: [] for api in proven_all_CWE_API}

    for branch in memory_summary['branch_analysis']:
        branch_calls = branch['calls']
        branch_conditions = branch['conditions']
        for api in proven_all_CWE_API:
            if api in branch_calls:
                condition_str = ' and '.join(branch_conditions) if branch_conditions else 'unconditional'
                api_conditions[api].append(condition_str)

    for api in proven_all_CWE_API:
        in_all = memory_summary['api_in_all_branches'][api]
        in_some = memory_summary['api_in_some_branches'][api]

        if in_all:
            summary = f"In the function {function_name}, all branches call {api}."
            summaries.append(summary)
        elif in_some:
            summary = f"In the function {function_name}, some branches call {api}."
            summaries.append(summary)
            # 列出具体的条件分支
            conditions_list = api_conditions[api]
            for condition in conditions_list:
                summary = f"In the function {function_name}, {'if ' + condition if condition != 'unconditional' else 'unconditional'}, {api} is called."
                summaries.append(summary)
        else:
            summary = f"In the function {function_name}, no branch calls {api}."
            summaries.append(summary)

    # 处理被调用的函数
    for callee_summary in memory_summary.get('callees', []):
        callee_name = callee_summary.get('function_name', '')
        if callee_name:
            summaries.append(f"In the function {function_name}, {callee_name} is called.")
            callee_summaries = summarize_memory_usage(callee_summary, {}, proven_all_CWE_API)
            summaries.append(callee_summaries)

    return "\n".join(summaries)

def analyze_memory_usage(dot_data, function_node_id, proven_all_CWE_API, max_depth):
    call_summaries, call_sequences = [], []
    call_nodes = find_call_nodes(dot_data, function_node_id[0])
    if call_nodes is None:
        logger.info(f"processing call node in analyze memory usage, call_nodes is None?")
        return None, None
    for call_node in call_nodes:
        node_data = dot_data.nodes[call_node]
        logger.info(f"processing call node in analyze memory usage: {call_node}")
        if '{' in node_data.get('CODE', ''):
            callee_summary = analyze_callee_memory_usage(dot_data, call_node, proven_all_CWE_API, depth=1, max_depth=max_depth)
            if callee_summary is None:
                logger.warning(f"Callee summary for node {call_node} is None.")
                continue

            call_summaries.append(callee_summary)
            alloc_summary = summarize_memory_usage(callee_summary, node_data, proven_all_CWE_API)
            call_sequences.append(alloc_summary)
            # logger.info(f"- Summary:\n {alloc_summary}")

    return call_summaries, call_sequences

def process_item_test(path, IterationLayer, proven_all_CWE_API, function_name, file):
    dot_file_path = path + "/export.dot"
    if not os.path.isfile(dot_file_path):
        return None
    print("processing: " + dot_file_path)
    try:
        graph = parse_dot_for_calls_and_cfgs_all(dot_file_path)
        # graph, key_function_node = parse_dot_for_calls_and_cfgs(dot_file_path, function_name, file, IterationLayer)

        print("file name:", file)
        print("function name:", function_name)
        key_function_node = find_function_node(graph, function_name, file)
        if key_function_node:
            # logger.info(f"function node ID: {key_function_node}")
            summary, sequence = analyze_memory_usage(graph, key_function_node, proven_all_CWE_API, IterationLayer)
            del graph
            del key_function_node
            gc.collect()
            if sequence and len(sequence) > 0:
                print("API description:", sequence)
                return sequence
            return None
        else:
            print(f"Function '{function_name}' not found.")
            return None
    except Exception as e:
        print(f"Error processing: {str(e)}")
        return None

def debug():
    cwe = "401"
    file_name = "cwe-" + cwe + "-test.c"
    function_name = "main"  # 测试不同的函数名："main"、"level1"、"level2"
    path = "/home/yx/hdd/projects/patch_VD/data_collection/test_case_dot_file/cwe-" + cwe + "-test.c"
    IterationLayer = 3
    API = all_proven_all_CWE_APIs["CWE-" + cwe]
    # API = all_proven_all_CWE_APIs["CWE-415"]
    output = process_item_test(path, IterationLayer, API, function_name, file_name)

def process_item(item, IterationLayer, vulnerable, joern_result_dir, save_dir):
    # 设置信号处理，指定超时时长为 max_task_timeout
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(max_task_timeout)  # 超时600秒

    try:
        if vulnerable == "non_vul":
            project_name = item.project + "_origin_fixed_" + item.commit
        elif vulnerable == "vul":
            project_name = item.project + "_parent_buggy_" + item.parent_commit
        else:
            logger.warning("not specify vulnerable or not")
            signal.alarm(0)
            return None

        dot_file_path = joern_result_dir + project_name + "/export.dot"
        if not os.path.isfile(dot_file_path):
            signal.alarm(0)
            return None
        logger.info(f"Processing: {dot_file_path}")
        function_name, file = item.function_ID, item.file_ID
        logger.info(f"File name: {file}")
        logger.info(f"Function name: {function_name}")
        if not function_name or not file:
            signal.alarm(0)
            return None

        graph = parse_dot_for_calls_and_cfgs_all(dot_file_path)
        logger.info(f"Loaded graph success!")

        key_function_node = find_function_node(graph, function_name, file)
        # graph, key_function_node = parse_dot_for_calls_and_cfgs(dot_file_path, function_name, file, IterationLayer)

        if key_function_node:
            logger.info(f"Function node ID: {key_function_node[0]}")
            proven_API = all_proven_all_CWE_APIs[item.CWE_ID]
            logger.info(f"proven API: {proven_API}")
            summary, sequence = analyze_memory_usage(graph, key_function_node, proven_API, IterationLayer)
            logger.info(f"process analyze memory usage success!")

            del graph
            del key_function_node
            gc.collect()
            # if sequence:
            logger.info("API description:\n", sequence)
            new_item = item._replace(API_sequence=sequence, API_summary = summary)
            # single_save_file_name = item.CVE_ID + "_" +  item.CWE_ID + "_" + project_name + "_" + file + "_" + function_name
            single_save_file_name = f"{item.CVE_ID}_{item.CWE_ID}_{project_name}_{file}_{function_name}"
            save_file_path = os.path.join(save_dir, "temp", single_save_file_name)
            with open(save_file_path, 'a') as file:
                file.write('\n'.join(sequence))
            logger.info(f"saved in {save_file_path} success!")
            signal.alarm(0)  # 任务完成，取消超时报警
            return new_item
            # signal.alarm(0)  # 任务完成，取消超时报警
            # return None
        else:
            logger.warning(f"Function '{function_name}' not found.")
            signal.alarm(0)  # 任务完成，取消超时报警
            return None
    except TimeoutError:
        return None
    except Exception as e:
        logger.error(f"Error processing: {str(e)}")
        return None


def main():
    parser = argparse.ArgumentParser(description="示例 argparse 脚本")
    parser.add_argument("-s", "--server", type=str)
    parser.add_argument("-v", "--vulnerable", type=str)
    parser.add_argument("-m", "--maxworker", type=int)
    parser.add_argument("-l", "--IterationLayer", type=int)

    # 解析参数
    args = parser.parse_args()
    if args.server == "49":
        # 49
        print("running on 49...")
        joern_result_dir = "/l1/yx/NVD/joern_result/export_output/"
        origin_data_dir = "/l1/yx/NVD/all_NVD_with_function_with_parent/"
        save_dir = "/l2/yx/NVD/all_NVD_with_function_with_parent_with_API/"
    elif args.server == "47":
        # 47
        print("running on 47...")
        joern_result_dir = "/l2/yx/NVD/joern_result/export_output/"
        origin_data_dir = "/l1/yx/NVD/all_NVD_with_function_with_parent/"
        save_dir = "/l1/yx/NVD/all_NVD_with_function_with_parent_with_API/"
    else:
        print("not specify server!")
        return

    if not os.path.isdir(save_dir):
        os.mkdir(save_dir)

    if not os.path.isdir(save_dir + "temp/"):
        os.mkdir(save_dir + "temp/")

    if args.vulnerable == "non_vul":
        # non_vul
        print("extract not vulnerable samples...")
        data = read_pkl(origin_data_dir)[0]
        save_file = save_dir + 'non_vul_files_with_API_1023.pkl'
        flag = "_origin_fixed_"
    elif args.vulnerable == "vul":
        # vul
        print("extract vulnerable samples...")
        data = read_pkl(origin_data_dir)[1]
        save_file = save_dir + 'vul_files_with_API_1023.pkl'
    else:
        print("not specify vulnerability!")
        return


    proven_list = []
    for doc in data:
        # if doc.CWE_ID in proven_all_CWE and "wireshark" in doc.project:
        if doc.CWE_ID in proven_all_CWE:
            proven_list.append(doc)

    del data
    gc.collect()

    max_workers = args.maxworker if args.maxworker else 2
    IterationLayer = args.IterationLayer if args.IterationLayer else 3


    log_file_name = "extract_" + args.vulnerable + "_" + str(max_workers) + "_" + str(IterationLayer) + ".log"

    listener = setup_logging(save_dir, log_file_name)

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_item, item, args.IterationLayer, args.vulnerable, joern_result_dir, save_dir) for item in proven_list]
        # 收集结果
        new_data = []
        for future in as_completed(futures):
            try:
                result = future.result(timeout=max_task_timeout)
                if result is not None:
                    new_data.append(result)
            except concurrent.futures.TimeoutError:
                logger.error(f"Task timed out after {max_task_timeout} seconds.")
            except Exception as e:
                logger.error(f"Task failed with exception: {str(e)}")

    with open(save_file, 'wb') as f:
        pickle.dump(new_data, f)



if __name__ == '__main__':
    # main()
    debug()
