# #!/bin/bash

bin_dir="/data/linjk/bindata/binary"
export bin_dir

# python3 get_src_info.py

ARCH_OPT=("arm_O1" "arm_O2" "arm_O3"
          "x86_O1" "x86_O2" "x86_O3" 
          "x64_O1" "x64_O3")

# ARCH_OPT=("x64_O3")
for arch_opt in "${ARCH_OPT[@]}"; do
    export arch_opt

    bash preprocess/get_bin_info.sh

    bash preprocess/get_cfg_cg.sh

    find $bin_dir/$arch_opt -type f -name "*_extract.pkl.gz" > $bin_dir/$arch_opt/test.txt

    find $bin_dir/$arch_opt -type f -name "*_extract_for_cg.pkl.gz" > $bin_dir/$arch_opt/test_for_cg.txt

    python3 preprocess/collect.py

    python3 preprocess/analyze.py

    python3 preprocess/get_cfg_cg.py

    python3 match_src_bin.py

    # break
done