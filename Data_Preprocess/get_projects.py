# -*- coding: utf-8 -*-

import json
import collections
import pickle
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os

# 定义全局锁
git_lock = threading.Lock()

CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name')
max_workers = 30
diff_root_path = "/home/yx/hdd/projects/patch_VD/Dataset/NVD-new/5_TypeDiffs/"
project_repo_root_path = "/l1/yx/NVD/project_repos/"

# 47
root_save_path = "/l1/yx/NVD/vul_nonvul_projects/"
# 49
# root_save_path = "/home/yx/hdd/projects/patch_VD_results/NVD/vul_nonvul_projects/"
# root_save_path = "/l2/yx/NVD/vul_nonvul_projects/"

info = {
            # 47
            "binutils": {"org": "bminor", "repo": "binutils-gdb", "sha": []},
             "asterisk": {"org": "asterisk", "repo": "asterisk", "sha": []}, #
             "chrome": {"org": "chromium", "repo": "chromium", "sha": []},
             "ffmpeg": {"org": "FFmpeg", "repo": "FFmpeg", "sha": []}, #
             "firefox": {"org": "mozilla", "repo": "gecko-dev", "sha": []},
             # https://hg.mozilla.org/mozilla-central/shortlog
             "imagemagick": {"org": "ImageMagick", "repo": "ImageMagick", "sha": []}, #
             "jasper": {"org": "jasper-software", "repo": "jasper", "sha": []}, #
             "libming": {"org": "libming", "repo": "libming", "sha": []}, #
              "libtiff": {"org": "vadz", "repo": "libtiff", "sha": []},
              "openssl": {"org": "openssl", "repo": "openssl", "sha": []},
              "xen": {"org": "xen-project", "repo": "xen", "sha": []}
             # 49
             # "libpng": {"org": "pnggroup", "repo": "libpng", "sha": []}, #
             # "linux_kernel": {"org": "torvalds", "repo": "linux", "sha": []},
             # "php": {"org": "php", "repo": "php-src", "sha": []}, #
             # "qemu": {"org": "qemu", "repo": "qemu", "sha": []},  #
             # "vlc_media_player": {"org": "videolan", "repo": "vlc", "sha": []},  #
             # "wireshark": {"org": "wireshark", "repo": "wireshark", "sha": []},
             }

def clone_repo(repo_url, location):
    """Clone a git repository to a specified location."""
    subprocess.run(["git", "clone", repo_url, location], check=True)

def run_command(command, cwd=None):
    """运行单个命令并返回结果"""
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
        return result
    except subprocess.CalledProcessError as e:
        return e

def run_cp_command(cp_cmd, repo_path):
    # # 使用 Popen 执行命令
    # proc = subprocess.Popen(cp_cmd, shell=True, cwd=repo_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    #                         stderr=subprocess.PIPE)

    proc = subprocess.Popen(cp_cmd, cwd=repo_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # 向 stdin 发送密码
    # proc.stdin.write(f"{password}\n".encode())
    # proc.stdin.flush()
    # 等待命令执行完成
    stdout, stderr = proc.communicate()

    # 检查返回码
    if proc.returncode == 0:
        print("Copy successful.")
    else:
        print(f"Copy failed with return code {proc.returncode}.")

def checkout_commit(repo_path, commit_id, save_path):
    """Checkout a specific commit and save the project state."""
    # # Ensure the repository is at the given path
    # os.chdir(repo_path)
    # if not os.path.isdir(save_path):
    #     os.mkdir(save_path)
    # # subprocess.run(["git", "checkout", commit_id], check=True)
    # # # Copy the directory content to save path
    # # subprocess.run(["cp", "-r", ".", save_path], check=True)
    # result = run_command(["git", "checkout", commit_id])
    # print(" ".join(["git", "checkout:", repo_path, "->", commit_id]))
    # if result != "error":
    #     run_command(["echo", "yx2023", "|", "sudo", "-S", "cp", "-r", ".", save_path])
    #     print(" ".join(["echo", "yx2023", "|", "sudo", "-S", "cp", "-r", ".", save_path]))

    if not os.path.isdir(save_path):
        os.mkdir(save_path)
    # 进入源目录并执行git checkout命令
    with git_lock:
        # 确保工作目录没有未提交修改和未跟踪文件
        stash_result = run_command(["git", "stash", "--include-untracked"], cwd=repo_path)
        if isinstance(stash_result, subprocess.CalledProcessError):
            print(f"Stash failed in {repo_path}: {stash_result.stderr}")
            return

        git_checkout_cmd = ["git", "checkout", commit_id]
        checkout_result = run_command(git_checkout_cmd, cwd=repo_path)
        if isinstance(checkout_result, subprocess.CalledProcessError) or checkout_result.returncode != 0:
            print(f"Checkout failed for {commit_id} in {repo_path}: {checkout_result.stderr}")
            print(checkout_result)
            return
        print(f"Checkout succeeded for {commit_id} in {repo_path}")

        # 确保所有文件被重置到正确的状态
        git_reset_cmd = ["git", "reset", "--hard", commit_id]
        reset_result = run_command(git_reset_cmd, cwd=repo_path)
        if isinstance(reset_result, subprocess.CalledProcessError) or reset_result.returncode != 0:
            print(f"Git reset failed in {repo_path}: {reset_result.stderr}")
            return

        # 确保工作树是干净的
        git_clean_cmd = ["git", "clean", "-fdx"]
        clean_result = run_command(git_clean_cmd, cwd=repo_path)
        if isinstance(clean_result, subprocess.CalledProcessError) or clean_result.returncode != 0:
            print(f"Git clean failed in {repo_path}: {clean_result.stderr}")
            return

        # 将checkout成功的项目复制到新路径下
        rsync_cp_cmd = ["rsync", "-av", "--exclude", ".git", repo_path + "/", save_path + "/"]
        copy_result = run_command(rsync_cp_cmd)
        if isinstance(copy_result, subprocess.CalledProcessError) or copy_result.returncode != 0:
            print(f"Copy failed from {repo_path} to {save_path}: {copy_result.stderr}")
            return
        else:
            print(f"Copy succeeded from {repo_path} to {save_path}")

        # 删除新路径下项目的.git目录节省空间
        git_dir = save_path + "/" + ".git"
        if os.path.isdir(git_dir):
            rm_dir = ["rm", "-r", git_dir]
            rm_result = run_command(rm_dir)



def process_projects(item):
    """Process each project and CVE."""
    project_repo_name = info[item.project]["repo"]
    project_repo_path = os.path.join(project_repo_root_path, project_repo_name)
    origin_commit_id = item.commit
    # origin_commit_path = os.path.join(root_save_path, item.project + "_origin_fixed_" + origin_commit_id)
    parent_commit_id = item.parent_commit
    # parent_commit_path = os.path.join(root_save_path, item.project + "_parent_buggy_" + parent_commit_id)

    origin_fixed_path = os.path.join(root_save_path, item.project + "_origin_fixed_" + origin_commit_id)
    parent_buggy_path = os.path.join(root_save_path, item.project + "_parent_buggy_" + parent_commit_id)
    if len(origin_commit_id)==40 and os.path.isdir(project_repo_path) and not os.path.isdir(origin_fixed_path):
        # Save the CVE commit version
        print("checkout " + origin_fixed_path)
        checkout_commit(project_repo_path, origin_commit_id, origin_fixed_path)
    if len(parent_commit_id) == 40 and os.path.isdir(project_repo_path) and not os.path.isdir(parent_buggy_path):
        # Save the parent commit version
        print("checkout " + parent_buggy_path)
        checkout_commit(project_repo_path, parent_commit_id, parent_buggy_path)



def main():
    all_data_path = "/l1/yx/NVD/all_NVD_with_parent/non_vul_files.pkl"
    with open(all_data_path, 'rb') as f:
        all_data_with_parent_commit = pickle.load(f)

    if not os.path.isdir(root_save_path):
        os.mkdir(root_save_path)


    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_projects, item) for item in all_data_with_parent_commit if item.project in info.keys()]
        for future in as_completed(futures):
            try:
                future.result()  # 获取结果，触发异常处理
            except Exception as e:
                print(f"Task failed with exception: {e}")



if __name__ == '__main__':
    main()
