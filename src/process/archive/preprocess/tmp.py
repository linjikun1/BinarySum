import json
import os

root_dir = "/home/linjk/study/data/dataset/my_data/binary/x64_O2"

for project_name in os.listdir(root_dir):
    if project_name != 'vmlinux':
        continue
    project_path = os.path.join(root_dir, project_name)
    unstrip_project_path = os.path.join(project_path, "unstrip")
    for file_name in os.listdir(project_path):
        if file_name.endswith('.json'):
            file_path = os.path.join(project_path, file_name)
            with open(file_path, 'r') as f:
                data = json.load(f)
                print(len(data))
                for addr, item in data.items():
                    if item['strip_function_name'] == 'sub_FFFFFFFF81A90620':
                        print(f"Project: {project_name}, File: {file_name}, Function: {item['strip_function_name']}")
                    if hex(int(addr)) == '0xFFFFFFFF81A90620':
                        print(f"Project: {project_name}, File: {file_name}, Function: {item['strip_function_name']}")
    for file_name in os.listdir(unstrip_project_path):
        if file_name.endswith('.json'):
            file_path = os.path.join(unstrip_project_path, file_name)
            with open(file_path, 'r') as f:
                data = json.load(f)
                for _, item in data.items():
                    if item['function_name'] == 'gss_del_sec_context':
                        print(f"Project: {project_name}, File: {file_name}, Function: {item['strip_function_name']}")
    