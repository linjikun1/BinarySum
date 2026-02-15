### 测试命令
- 处理 cpbcs 相关信息
    ```bash
    /home/linjk/tools/ida-pro-9.0/idat -A -L"ida.log" -S"get_cpbcs_info.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/addr2line.elf.elf
    ```

- 获取 strip_addr_code 信息
    ```bash
    /home/linjk/tools/ida-pro-9.0/idat -A -L"ida.log" -S"get_strip_code.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/addr2line.elf.elf
    ```

- 获取 unstrip_addr_code 信息
    ```bash
    /home/linjk/tools/ida-pro-9.0/idat -A -L"ida.log" -S"get_unstrip_code.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/unstrip/addr2line.elf.elf
    ```

- 获取 cfg 信息
    ```bash
    /home/linjk/tools/ida-pro-9.0/idat -A -L"ida.log" -S"get_cfg.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/addr2line.elf.elf
    ```

- pkl 文件信息
    ```bash
    find /home/linjk/study/data/dataset/my_data/binary/x64_O2 -type f -name "*_extract.pkl" > /home/linjk/study/data/dataset/my_data/binary/test.txt
    ```

    ```bash
    find /home/linjk/study/data/dataset/my_data/binary/x64_O2 -type f -name "*_extract_for_cg.pkl" > /home/linjk/study/data/dataset/my_data/binary/test_cg.txt
    ```

- collect pkl 文件
    ```bash
    python collect.py
    ```

- analyze pkl 文件
    ```bash
    python analyze.py
    ```

### 其它
- 删除多余文件
    ```bash
    find . -type f ! -name "*.elf" -delete
    ```

- 删除.pkl文件
    ```bash
    find . -type f -name "*.pkl" -exec rm -f {} +
    ```

- dwarf信息
    ```bash
    /home/linjk/tools/ida-pro-9.0/idat -A -L"log.log" -S"get_dwarf.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/apr/unstrip/libapr-1.so.0.7.0.elf
    ```