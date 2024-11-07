# -*- coding: utf-8 -*-

import json
import time
import requests
import pandas as pd
import collections
import pickle
import os
import re

CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name file function')

api_key = ""

headers = {
    "Authorization": "Token " + api_key,
    "Accept": "application/vnd.github.v3+json"
}

def read_CVE_fixes_in_dataframe():
    df = pd.read_csv('/l1/yx/CVEfixes_whole.csv')
    new_df = pd.DataFrame(columns=["dataframe_line", "CVE", "Commit", "Parent"])
    i = 0
    for index, row in df.iterrows():
        print("index: ", index)
        cwe = row['cwe_id']
        print("CWE: ", cwe)
        commit_id = row['original_address']
        print("Commit ID: ", commit_id)
        org, repo, sha = commit_id.split('/')[-4], commit_id.split('/')[-3], commit_id.split('/')[-1]
        parent = get_parent_sha(org, repo, sha, cwe)
        # time.sleep(5)
        if parent == "no":
            continue
        else:
            # insert to new_df
            new_df.loc[i] = [index, cwe, commit_id, parent]
            i += 1
    new_df.to_csv("/l1/yx/map_CVE_fixes_whole.csv", index=False)

def read_csv_in_dataframe():
    df = pd.read_csv('/l1/yx/all_c_cpp_release2.0.csv')
    new_df = pd.DataFrame(columns=["CVE", "Commit", "Parent"])
    i = 0
    for index, row in df.iterrows():
        print("index: ", index)
        cve = row['cve_id']
        print("CVE: ", cve)
        commit_id = row['ref_link']
        print("Commit ID: ", commit_id)
        org, repo, sha = commit_id.split('/')[-4], commit_id.split('/')[-3], commit_id.split('/')[-1]
        parent = get_parent_sha(org, repo, sha, cve)
        # time.sleep(5)
        if parent == "no":
            continue
        else:
            # insert to new_df
            new_df.loc[i] = [cve, commit_id, parent]
            i += 1
    new_df.to_csv("/l1/yx/map_all_c_cpp_release2.0.csv", index=False)

def get_parent_sha(org, repo, sha, cve):
    url_api = f"https://api.github.com/repos/{org}/{repo}/commits/{sha}"
    print("API URL: ", url_api)

    count_1 = 0
    flag_1 = False
    while count_1 < 10:
        try:
            response = requests.get(url_api, headers=headers)
            break
        except:
            count_1 += 1
            time.sleep(count_1 * 3)
            if count_1 == 10:
                print("Exception when first requesting!")
                flag_1 = True

    if flag_1:
        with open("/l1/yx/get_parent_log/bv_failed.txt", 'w') as f:
            f.write(cve)
            f.write('\n')
        return "no"

    if response.status_code == 200:
        events = json.loads(response.text)
    else:
        print("Exception with status code!")
        with open("/l1/yx/get_parent_log/bv_failed.txt", 'w') as f:
            f.write(cve)
            f.write('\n')
        return "no"

    if events["parents"] is not None:
        parent_sha = events["parents"][0]["sha"]
        print("Get parent sha successfully.")
    else:
        print("No parents.")
        with open("/l1/yx/get_parent_log/bv_no_parents.txt", 'w') as f:
            f.write(cve)
            f.write('\n')
        return "no"

    parent = f"https://api.github.com/repos/{org}/{repo}/commits/{parent_sha}"
    return parent


def read_NVD_in_code(non_vuls, vuls, infos):
    new_non_vuls, new_vuls = [], []
    unique_commit = dict()
    for item in non_vuls:
        sha = item.commit
        print("------------------------------------")
        print("commit ID:", sha)
        if sha not in unique_commit.keys():
            project = item.project
            org = infos[project]["org"]
            repo = infos[project]["repo"]
            cve = item.CVE_ID
            parent_id = get_parent_sha(org, repo, sha, cve).split("/")[-1]
            # time.sleep(5)
            print("parent commit ID:", parent_id)
            item = item._replace(parent_commit = parent_id)
            unique_commit[sha] = parent_id
        else:
            item = item._replace(parent_commit=unique_commit[sha])
        new_non_vuls.append(item)

    for item in vuls:
        sha = item.commit
        item = item._replace(parent_commit=unique_commit[sha])
        # item.parent_commit = unique_commit[sha]
        new_vuls.append(item)
    save_data(new_non_vuls, new_vuls, "/l1/yx/NVD/all_NVD_with_parent/")

def save_data(non_vul_files, vul_files, save_dir):
    with open(save_dir + 'non_vul_files.pkl', 'wb') as f:
        pickle.dump(non_vul_files, f)
    with open(save_dir + 'vul_files.pkl', 'wb') as f:
        pickle.dump(vul_files, f)

def read_pkl(save_dir):
    # save_dir = "/l1/yx/NVD/"
    with open(save_dir + 'non_vul_files_old.pkl', 'rb') as f:
        non_vul = pickle.load(f)
    with open(save_dir + 'vul_files_old.pkl', 'rb') as f:
        vul = pickle.load(f)
    return non_vul, vul


def main():
    save_dir = "/l1/yx/NVD/all_NVD_with_parent_function_file/"
    non_vul, vul = read_pkl(save_dir)
    infos = {"binutils":{"org":"bminor", "repo":"binutils-gdb", "sha":[]},
             "asterisk":{"org":"asterisk", "repo":"asterisk", "sha":[]},
             "chrome":{"org":"chromium", "repo":"chromium", "sha":[]},
             "ffmpeg":{"org":"FFmpeg", "repo":"FFmpeg", "sha":[]},
             "firefox":{"org":"mozilla", "repo":"gecko-dev", "sha":[]},
             # https://hg.mozilla.org/mozilla-central/shortlog
             "imagemagick":{"org":"ImageMagick", "repo":"ImageMagick", "sha":[]},
             "jasper":{"org":"jasper-software", "repo":"jasper", "sha":[]},
             "libming":{"org":"libming", "repo":"libming", "sha":[]},
             "libpng":{"org":"pnggroup", "repo":"libpng", "sha":[]},
             "libtiff":{"org":"vadz", "repo":"libtiff", "sha":[]},
             "linux_kernel": {"org": "torvalds", "repo": "linux", "sha": []},
             "openssl": {"org": "openssl", "repo": "openssl", "sha": []},
             "php": {"org": "php", "repo": "php-src", "sha": []},
             "qemu": {"org": "qemu", "repo": "qemu", "sha": []},
             "vlc_media_player": {"org": "videolan", "repo": "vlc", "sha": []},
             "wireshark": {"org": "wireshark", "repo": "wireshark", "sha": []},
             "xen": {"org": "xen-project", "repo": "xen", "sha": []}
             }
    os.system("export https_proxy=http://127.0.0.1:7890")
    # os.system("curl -v https://google.com")
    read_NVD_in_code(non_vul, vul, infos)

def main2():
    save_path = "/l1/yx/NVD/all_NVD_with_parent/"
    new_non_vul, new_vul = [], []
    non_vul, vul = read_pkl(save_path)
    print()
#     for item in non_vul:
#         file, function = extract_info(item.file_name)
#         item = item._replace(file = file, function = function)
#         new_non_vul.append(item)
#
#     for item in vul:
#         file, function = extract_info(item.file_name)
#         item = item._replace(file = file, function = function)
#         new_vul.append(item)
#     save_data(new_non_vul, new_vul, "/l1/yx/NVD/all_NVD_with_parent_function_file/")
#     print()

# def main3():
#     # 示例字符串
#     strings = [
#         "CVE-2009-2347_CWE-189_81b47fab54c5a2d13e4032c604073f3d948872a3_rgb2ycbcr.c_1.1_tiffcvt_NEW.c",
#         "CVE-2009-2347_CWE-189_81b47fab54c5a2d13e4032c604073f3d948872a3_tiff2rgba.c_1.1_cvt_whole_image_NEW.c",
#         "CVE-2011-1167_CWE-119_68add62b33402ac5964f7aa2ed30806bce33da61_tif_thunder.c_2.1_TIFFInitThunderScan_OLD.c",
#         "CVE-2017-7602_CWE-190_66e7bd59520996740e4df5495a830b42fae48bc4_blogsgentoo0_tif_read.c_4.0_TIFFReadRawStrip1_NEW.c"
#     ]
#
#     # 提取信息
#     for string in strings:
#         file_name, func_name = extract_info(string)
#         if file_name and func_name:
#             print(f"File Name: {file_name}, Function Name: {func_name}")
#         else:
#             print(f"Failed to extract from: {string}")


if __name__ == "__main__":
    # read_csv_in_dataframe()
    # read_CVE_fixes_in_dataframe()
    # read_NVD_in_code()
    # main()
    main2()
    # main3()