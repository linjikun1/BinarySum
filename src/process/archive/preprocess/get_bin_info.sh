#!/bin/bash

# 定义根目录和脚本路径
LOG="ida.log"
BIN_DATA_ROOT="$bin_dir/$arch_opt"
GET_CPBCS_INFO_SCRIPT="$PWD/preprocess/get_cpbcs_info.py"
GET_STRIP_CODE_SCRIPT="$PWD/preprocess/get_strip_code.py"
GET_UNSTRIP_CODE_SCRIPT="$PWD/preprocess/get_unstrip_code.py"
GET_UNSTRIP_CODE_SCRIPT_FIXED="$PWD/preprocess/get_unstrip_code_fixed.py"
GET_BIN_DATA_SCRIPT="$PWD/preprocess/get_bin_data.py"

IDA_EXECUTABLE="/data/tool/ida-pro-9.1/idat"

# 遍历项目目录
for project in "$BIN_DATA_ROOT"/*; do
	echo "$project"
	project_name=$(basename "$project")
	if [[ -d "$project" ]]; then
		SAVEROOT="$project/extracted-bins"
		DATAROOT="$project/unstrip"

		# 检查目录是否存在
		if [[ ! -d "$SAVEROOT" || ! -d "$DATAROOT" ]]; then
			echo "[!] Skipping $(basename "$project"): 'extracted-bins' or 'unstrip' directory not found."
			continue
		fi

		# 设置临时环境变量
		export SAVEROOT
		export DATAROOT

		echo "[+] Processing project: $(basename "$project")"
		echo "    SAVEROOT=$SAVEROOT"
		echo "    DATAROOT=$DATAROOT"

		for binary_file in "$project"/*.elf; do
			if [[ -f "$binary_file" ]]; then
				echo "[+] Processing ELF binary: $binary_file"

				# 构建并执行 IDA 命令
				$IDA_EXECUTABLE -A -L"$LOG" -S"$GET_CPBCS_INFO_SCRIPT" "$binary_file"
				$IDA_EXECUTABLE -A -L"$LOG" -S"$GET_STRIP_CODE_SCRIPT" "$binary_file"
				$IDA_EXECUTABLE -A -L"$LOG" -S"$GET_UNSTRIP_CODE_SCRIPT" "$(dirname "$binary_file")/unstrip/$(basename "$binary_file")"
				$IDA_EXECUTABLE -A -L"$LOG" -S"$GET_UNSTRIP_CODE_SCRIPT_FIXED" "$(dirname "$binary_file")/unstrip/$(basename "$binary_file")"
				$IDA_EXECUTABLE -A -L"$LOG" -S"$GET_BIN_DATA_SCRIPT" "$binary_file"

				if [[ $? -ne 0 ]]; then
					echo "[!] Error processing $binary_file. Check $LOG for details."
				else
					echo "[*] Successfully processed $binary_file."
				fi
			fi
		done
	fi
done

echo "[*] All projects processed."
