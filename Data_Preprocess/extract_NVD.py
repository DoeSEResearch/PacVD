# -*- coding: utf-8 -*-

import collections
import pickle
import os
import re

# 定义命名元组
CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID API_summary API_sequence')

def extract_info(string):
    # 移除前面的 CVE ID、CWE ID 和 commit 部分
    parts = string.split('_', 3)
    if len(parts) < 4:
        return None, None

    remaining_string = parts[3]

    # 定义正则表达式以匹配所需的文件名和函数名
    regex = re.compile(r"""
        (?P<file_name>[\w\-]+\.c)_          # 匹配文件名，包括字母、数字、下划线和点
        (?:\d+\.\d+_)?                      # 可选的版本号
        (?P<func_name>[\w\-]+)              # 匹配函数名，包括字母、数字、下划线和点
        _                                   # 下划线分隔符
        (NEW|OLD)\.c$                       # 匹配 NEW.c 或 OLD.c 结尾
        |
        (?P<file_name_no_version>[\w\-]+\.c)# 匹配文件名，没有版本号
        _                                   # 下划线分隔符
        (?P<func_name_no_version>[\w\-]+)   # 匹配函数名，没有版本号
        _                                   # 下划线分隔符
        (NEW|OLD)\.c$                       # 匹配 NEW.c 或 OLD.c 结尾
    """, re.VERBOSE)

    match = regex.match(remaining_string)
    if match:
        file_name = match.group('file_name') or match.group('file_name_no_version')
        func_name = match.group('func_name') or match.group('func_name_no_version')
        print("_______________________match________________________")
        print("whole file:", string)
        print("function_id", func_name)
        print("file_id", file_name)

        # 去掉函数名开头的下划线
        func_name = func_name.lstrip('_')
        return file_name, func_name
    else:
        print("_____________________do not match_________________")
        print("whole file:", string)
        return None, None
def process_files(root_dir):
    vul_files = []
    non_vul_files = []

    # 遍历根目录
    for project in os.listdir(root_dir):
        project_path = os.path.join(root_dir, project)
        if os.path.isdir(project_path):
            # 遍历每个项目下的CVE目录
            for cve in os.listdir(project_path):
                cve_path = os.path.join(project_path, cve)
                if os.path.isdir(cve_path):
                    # 遍历CVE目录下的文件
                    for file in os.listdir(cve_path):
                        if file.endswith('_NEW.c') or file.endswith('_OLD.c'):
                            file_path = os.path.join(cve_path, file)
                            # print("file:", file_path)
                            data = read_file(file_path)
                            commit = extract_commit(file)
                            CWE_ID = extract_cwe(file)
                            file_ID, function_ID = extract_info(file)

                            if file.endswith('_NEW.c'):
                                # 处理非漏洞文件
                                file_data = CodeDocument(
                                    words=data,
                                    cls = 0,
                                    project=project,
                                    CVE_ID=cve,
                                    CWE_ID=CWE_ID,
                                    commit=commit,
                                    parent_commit="",
                                    file_name=file,
                                    file_ID=file_ID,
                                    function_ID=function_ID,
                                    API_summary="",
                                    API_sequence=""
                                )
                                non_vul_files.append(file_data)
                            elif file.endswith('_OLD.c'):
                                # 处理漏洞文件
                                file_data = CodeDocument(
                                    words=data,
                                    cls = 1,
                                    project=project,
                                    CVE_ID=cve,
                                    CWE_ID=CWE_ID,
                                    commit=commit,
                                    parent_commit="",
                                    file_name=file,
                                    file_ID=file_ID,
                                    function_ID=function_ID,
                                    API_summary="",
                                    API_sequence=""
                                )
                                vul_files.append(file_data)

    return non_vul_files, vul_files

def process_file_for_diffs(root_dir):
    all_diffs = []
    # 遍历根目录
    for project in os.listdir(root_dir):
        project_path = os.path.join(root_dir, project)
        if os.path.isdir(project_path):
            # 遍历每个项目下的CVE目录
            for cve in os.listdir(project_path):
                cve_path = os.path.join(project_path, cve)
                if os.path.isdir(cve_path):
                    # 遍历CVE目录下的文件
                    for file in os.listdir(cve_path):
                        file_path = os.path.join(cve_path, file)
                        file_data = CodeDocument(
                            words="",
                            cls=0,
                            project=project,
                            CVE_ID=cve,
                            commit=extract_commit(file),
                            parent_commit="",
                            CWE_ID=extract_cwe(file),
                            file_name=file
                        )
def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def extract_commit(file_name):
    # 示例从文件名中提取提交ID的假设逻辑
    return file_name.split('_')[2]

def extract_cwe(file_name):
    # 示例从文件名中提取CWE ID的假设逻辑
    return file_name.split('_')[1]

def save_data(non_vul_files, vul_files, save_dir):
    with open(save_dir + 'non_vul_files.pkl', 'wb') as f:
        pickle.dump(non_vul_files, f)
    with open(save_dir + 'vul_files.pkl', 'wb') as f:
        pickle.dump(vul_files, f)

def write_data(non_vul_files, vul_files, save_dir):
    with open(save_dir + "non_vul_files.txt", 'w') as file:
        for item in non_vul_files:
            file.write("%s\n" % item)
    with open(save_dir + "vul_files.txt", 'w') as file:
        for itemm in vul_files:
            file.write("%s\n" % itemm)

def read_pkl(save_dir):
    # save_dir = "/l1/yx/NVD/"
    with open(save_dir + 'non_vul_files.pkl', 'rb') as f:
        non_vul = pickle.load(f)
    with open(save_dir + 'vul_files.pkl', 'rb') as f:
        vul = pickle.load(f)
    return non_vul, vul

def extract_memory_items(save_dir, save_dir_memory, memory_CWE):
    non_vul, vul = read_pkl(save_dir)
    non_vul_memory, vul_memory = [], []
    if not os.path.isdir(save_dir_memory):
        os.mkdir(save_dir_memory)
    for item in non_vul:
        if item.CWE_ID in memory_CWE:
            non_vul_memory.append(item)
    for item in vul:
        if item.CWE_ID in memory_CWE:
            vul_memory.append(item)
    save_data(non_vul_memory, vul_memory, save_dir_memory)

def main():
    print()
    # oldnewfuncs to codedocument
    # root_dir = "/home/yx/hdd/projects/patch_VD/Dataset/NVD-new/7_OldNewFuncs"
    # save_dir = "/l1/yx/NVD/all_NVD_with_parent_function_file/"
    # # save_dir_proven_memory = "/l1/yx/NVD/proven_memory/"
    # non_vul_files, vul_files = process_files(root_dir)
    # # save_data(non_vul_files, vul_files, save_dir)
    # write_data(non_vul_files, vul_files, save_dir)

    #
    # # save_dir = "/l1/yx/NVD/"
    # # save_dir_memory = "/l1/yx/NVD/memory/"
    #
    #
    # # memory_CWE = ["CWE-119", "CWE-120", "CWE-125", "CWE-126", "CWE-415", "CWE-416", "CWE-787", "CWE-476", "CWE-674",
    # #             "CWE-690", "CWE-761", "CWE-401", "CWE-772", "CWE-459", "CWE-362", "CWE-590", "CWE-825"]
    # # extract_memory_items(save_dir, save_dir_memory, memory_CWE)
    #
    # proven_all_CWE = ["CWE-401", "CWE-415", "CWE-416", "CWE-476", "CWE-404", "CWE-772", "CWE-459"]
    # extract_memory_items(save_dir, save_dir_proven_memory, proven_all_CWE)
    #
    # proven_fix_memoryusage_CWE = ["CWE-401", "CWE-415", "CWE-416"]
    #                               # ["CWE-401", "CWE-404", "CWE-772", "CWE-666", "CWE-775", "CWE-459", "CWE-415", "CWE-416"]
    # proven_fix_np_CWE = ["CWE-476"]
    # proven_fix_resource_CWE = ["CWE-404", "CWE-772", "CWE-459"]
    #     # ["CWE-404", "CWE-772", "CWE-459", "CWE-755", "CWE-770", "CWE-483", "CWE-666", "CWE-675", "CWE-820"]


def main2():
    # diff to codedocument
    diff_root_path = "/home/yx/hdd/projects/patch_VD/Dataset/NVD-new/5_TypeDiffs/"
    save_dir = "/l1/yx/NVD/NVD_with_diffs/"

def main3():
    root_dir = "/home/yx/hdd/projects/patch_VD/Dataset/NVD-new/7_OldNewFuncs"
    save_dir = "/l1/yx/NVD/temp/"
    non_vul_files, vul_files = process_files(root_dir)
    save_data(non_vul_files, vul_files, save_dir)
    # write_data(non_vul_files, vul_files, save_dir)

if __name__ == "__main__":
    main3()




# def main():
# # 文件夹的目录结构是7_OldNewFuncs/项目名称/CVE ID/_NEW.c或_OLD.c文件
# # 遍历7_OldNewFuncs文件夹
# # 对每个项目，遍历每个项目下面的每个CVE
# # 对每个CVE，取后缀为_NEW.c的文件为非漏洞文件，后缀为_OLD.c的文件为漏洞文件，将
# # 创建命名元组vul和no_vul存储漏洞文件和非漏洞文件，文件内容读取到words字段，项目名称读取到project字段，CVE ID读取到CVE_ID字段，文件名中的commit读取到commit字段，文件名中的CWE读取到CWE_ID字段，文件名读取到file_name字段
# # 将non_vul和vul两个命名元组写入两个pickle文件中
#     path = "/home/yx/hdd/PRISM/all_embedding/pickle_object/spotbugs/detect_bin/src/good"
#     all_code = pickle.load(open(path, "rb"))
#     print(all_code)
#
#
# if __name__ == '__main__':
#     main()