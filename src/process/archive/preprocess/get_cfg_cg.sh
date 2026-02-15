#!/bin/bash

LOG="ida.log"
BIN_DATA_ROOT="$bin_dir/$arch_opt"
SCRIPT="$PWD/preprocess/extract_cfg_cg.py"

IDA_EXECUTABLE="/data/tool/ida-pro-9.1/idat"

for project in "$BIN_DATA_ROOT"/*; do
	echo "$project"
	project_name=$(basename "$project")
	if [[ -d "$project" ]]; then

		echo "[+] Processing project: $(basename "$project")"

		for binary_file in "$project"/*.elf; do
			if [[ -f "$binary_file" ]]; then
				$IDA_EXECUTABLE -A -L"$LOG" -S"$SCRIPT" "$binary_file"
			fi
		done
	fi
	# break
done