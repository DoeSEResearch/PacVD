# -*- coding: utf-8 -*-

import os
import subprocess
# from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ProcessPoolExecutor, as_completed
import threading
import psutil
from threading import Semaphore
import time
import pickle
import collections

CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name')

#  # 47:source repos
# all_projects_source_dir = "/l1/yx/NVD/vul_nonvul_projects/"
# save_base_dir = "/l2/yx/NVD/"
# info = {
#     "binutils": {"org": "bminor", "repo": "binutils-gdb", "sha": []},
#      "asterisk": {"org": "asterisk", "repo": "asterisk", "sha": []}, #
#      "chrome": {"org": "chromium", "repo": "chromium", "sha": []},
#      "ffmpeg": {"org": "FFmpeg", "repo": "FFmpeg", "sha": []}, #
#      "firefox": {"org": "mozilla", "repo": "gecko-dev", "sha": []},
#      # https://hg.mozilla.org/mozilla-central/shortlog
#      "imagemagick": {"org": "ImageMagick", "repo": "ImageMagick", "sha": []}, #
#      "jasper": {"org": "jasper-software", "repo": "jasper", "sha": []}, #
#      "libming": {"org": "libming", "repo": "libming", "sha": []}, #
#     "libtiff": {"org": "vadz", "repo": "libtiff", "sha": []},
#       "openssl": {"org": "openssl", "repo": "openssl", "sha": []},
#       "xen": {"org": "xen-project", "repo": "xen", "sha": []}
# }

#
    # # 49-linux
# all_projects_source_dir = "/home/yx/hdd/projects/patch_VD_results/NVD/vul_nonvul_projects/"
# info = {
#  "linux_kernel": {"org": "torvalds", "repo": "linux", "sha": []},
# }

# # 49
all_projects_source_dir = "/l2/yx/NVD/vul_nonvul_projects/"
save_base_dir = "/l1/yx/NVD/"
info = {
 "libpng": {"org": "pnggroup", "repo": "libpng", "sha": []}, #
 "php": {"org": "php", "repo": "php-src", "sha": []}, #
 "qemu": {"org": "qemu", "repo": "qemu", "sha": []},  #
 "vlc_media_player": {"org": "videolan", "repo": "vlc", "sha": []},  #
 "wireshark": {"org": "wireshark", "repo": "wireshark", "sha": []},
}



parse_path = os.path.join(save_base_dir, "joern_result/parse_output")
export_path = os.path.join(save_base_dir, "joern_result/export_output")

joern_path = "/l1/yx/"
# joern_path = "/home/yx/hdd/utils/"
joern_parse = os.path.join(joern_path, "joern/joern-cli/joern-parse")
joern_export = os.path.join(joern_path,"joern/joern-cli/joern-export")
all_data_path = "/l1/yx/NVD/all_NVD_with_parent/non_vul_files.pkl"

with open(all_data_path, 'rb') as f:
    all_data_with_parent_commit = pickle.load(f)

# proven_all_CWE = ["CWE-401", "CWE-415", "CWE-416", "CWE-476", "CWE-404", "CWE-772", "CWE-459"]
proven_all_CWE = ["CWE-401", "CWE-415", "CWE-416",
                  "CWE-476",
                  "CWE-404",  "CWE-772","CWE-775", "CWE-459"]
new_dict = collections.defaultdict(set)

for CWE in proven_all_CWE:
    new_dict[CWE] = set()

for doc in all_data_with_parent_commit:
    if doc.CWE_ID in proven_all_CWE:
        project_id1 = doc.project + "_origin_fixed_" + doc.commit
        project_id2 = doc.project + "_parent_buggy_" + doc.parent_commit
        new_dict[doc.CWE_ID].add(project_id1)
        new_dict[doc.CWE_ID].add(project_id2)

if not os.path.isdir(os.path.join(save_base_dir, "joern_result")):
    os.mkdir(os.path.join(save_base_dir, "joern_result"))
if not os.path.isdir(parse_path):
    os.mkdir(parse_path)
if not os.path.isdir(export_path):
    os.mkdir(export_path)

# 初始并发进程数
max_workers = 3
semaphore = Semaphore(max_workers)
number = 0

def run_command(command, cwd=None):
    """运行单个命令并返回结果"""
    # print(command)
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True, encoding='utf-8',
            errors='ignore')
        return result
    except subprocess.CalledProcessError as e:
        return e

# 函数：解析单个项目
def parse_project(project_path):
    # with semaphore:
    project_name = os.path.basename(project_path)
    parse_dir = parse_path + "/" + project_name
    export_dir = os.path.join(export_path, project_name)

    # 使用 joern-parse 解析代码
    parse_cmd = [joern_parse, project_path, '--output', parse_dir]
    parse_result = run_command(parse_cmd)
    if isinstance(parse_result, subprocess.CalledProcessError):
        print(f"Parsing failed for {project_name}: {parse_result.stderr}")
        return

    # 使用 joern-export 导出结果为 DOT 图
    export_cmd = [joern_export, '--repr=all', '--format=dot', parse_dir, '--out', export_dir]
    export_result = run_command(export_cmd)
    if isinstance(export_result, subprocess.CalledProcessError):
        print(f"Exporting failed for {project_name}: {export_result.stderr}")
        return

    if os.path.isfile(export_dir + "/export.dot"):
        print("export successful!" + export_dir)
        rm_cmd = ['rm', "-rf", parse_dir]
        run_command(rm_cmd)
        print("remove parse " + parse_dir)

        rm_cmd2 = ['rm', "-rf", project_path]
        run_command(rm_cmd2)
        print("remove " + project_path)

    print(f"Processing completed for {project_name}")

def monitor_resources():
    """监控系统资源并动态调整信号量"""
    global semaphore
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        mem_usage = psutil.virtual_memory().percent
        # 如果CPU或内存使用超过70%，减少信号量值（最小值为1）
        if cpu_usage > 65 or mem_usage > 65:
            if semaphore._value > 1:
                semaphore = Semaphore(semaphore._value - 1)
        # 如果CPU和内存使用都低于50%，增加信号量值（最大值为 max_workers）
        elif cpu_usage < 50 and mem_usage < 50:
            if semaphore._value < max_workers:
                semaphore = Semaphore(semaphore._value + 1)

        time.sleep(5)  # 每5秒检查一次

def main():
    # max_workers = 5
    # 启动资源监控线程
    # monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
    # monitor_thread.start()

    # 获取主目录下的所有子目录（项目）
    # projects_path = [os.path.join(all_projects_source_dir, project) for project in os.listdir(all_projects_source_dir) if
    #             os.path.isdir(os.path.join(all_projects_source_dir, project)) and not os.path.isdir(os.path.join(export_path, project))]

    projects_path = []
    for CWE in proven_all_CWE:
        project_names = new_dict[CWE]
        for project_name in project_names:
            # if os.path.isdir(os.path.join(all_projects_source_dir, project_name)) and not os.path.isdir(os.path.join(export_path, project_name)):
            if "linux" not in project_name and os.path.isdir(os.path.join(all_projects_source_dir, project_name)) and not os.path.isdir(os.path.join(export_path, project_name)):
            # if "linux" in project_name and os.path.isdir(os.path.join(all_projects_source_dir, project_name)) and not os.path.isdir(os.path.join(export_path, project_name)):
            # if os.path.isdir(os.path.join(all_projects_source_dir, project_name)):
                projects_path.append(os.path.join(all_projects_source_dir, project_name))

    # 并行处理每个项目
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(parse_project, project_path) for project_path in projects_path]
        for future in as_completed(futures):
            try:
                future.result()  # 获取结果，触发异常处理
            except Exception as e:
                print(f"Task failed with exception: {e}")

if __name__ == '__main__':
    main()






