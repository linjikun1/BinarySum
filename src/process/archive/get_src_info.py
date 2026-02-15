#!/usr/bin/env python3
"""
extract_functions.py

递归扫描 C 项目，提取函数定义，并可选同时提取其**紧邻的块注释**。

输出 JSON 数组示例：
{
  "project": "linux",
  "file": "/path/fs/nilfs2/alloc.c",
  "function": "nilfs_alloc_inode",
  "source": "...完整源码...",
  "comment": "Allocate a new inode for NILFS filesystem"  # 当启用 --with-comments 时才包含
}

用法
----
```
python extract_functions.py <PROJECT_ROOT> <OUTPUT_JSON> [--with-comments]
```
- `<PROJECT_ROOT>`  : 顶层目录，脚本会递归查找其中的所有 .c 文件。
- `<OUTPUT_JSON>`   : 输出文件路径。
- `--with-comments` : (可选) 若指定，则在 JSON 中额外写入函数前的块注释首句。
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm

C_KEYWORDS = {
    "if", "else", "for", "while", "switch", "case", "do", "goto", "break",
    "continue", "default", "return", "sizeof", "typedef", "static", "inline",
    "extern", "struct", "union", "enum", "const", "volatile", "register",
    "unsigned", "signed", "void", "char", "int", "float", "double", "short",
    "long", "auto"
}

# -- 正则配置 ------------------------------------------------------------
FUNC_HEADER_RE = re.compile(
    r'''^\s*                                 # 行首可空白
        (?:static|inline|extern|unsigned|signed|struct|const|volatile)?\s* # 可选修饰符
        ([a-zA-Z_][\w\s\*]+)\s+              # 返回类型（只匹配以类型关键字开头）
        (?P<name>[a-zA-Z_]\w*)\s*            # 函数名
        \(\s*([^\)]*)\)\s*                   # 参数列表，允许内容随意
        \{                                   # 紧跟左大括号
    ''',
    re.MULTILINE | re.VERBOSE
)


# -- 辅助函数 ------------------------------------------------------------

def find_c_files(root: Path) -> List[Path]:
    """递归查找所有 .c 文件"""
    return [p for p in root.rglob("*.c") if p.is_file()]

def slice_function_body(text: str, start_idx: int) -> str:
    """在 text 中，从 start_idx 起计数括号取得函数完整源码块。"""
    brace = 0
    for i in range(start_idx, len(text)):
        ch = text[i]
        if ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
            if brace == 0:
                return text[start_idx : i + 1]
    return ""  # 未闭合

def preceding_block_comment(lines: List[str], def_line_idx: int) -> Optional[str]:
    """向上查找紧挨函数定义之前的注释（块注释或行注释），返回首句文本。"""
    # def_line_idx 指向函数头所在行号
    i = def_line_idx - 1
    
    # 跳过空行
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    
    # 如果已经没有更多行了
    if i < 0:
        return None
    
    comment_lines = []
    
    # 检查是哪种类型的注释
    if lines[i].strip().endswith("*/"):
        # 处理块注释 /* */
        while i >= 0:
            line = lines[i]
            comment_lines.insert(0, line)
            if "/*" in line:
                break
            i -= 1
        
        # 如果没有找到 /* 开始符号
        if i < 0 or "/*" not in lines[i]:
            return None
            
        # 拼成单段文本
        comment_text = " ".join(l.strip("/* ") for l in comment_lines)
        
    elif lines[i].strip().startswith("//"):
        # 处理单行注释 //
        while i >= 0 and lines[i].strip().startswith("//"):
            comment_lines.insert(0, lines[i].strip()[2:].strip())  # 去掉 //
            i -= 1
            
        # 拼成单段文本
        comment_text = " ".join(comment_lines)
        
    else:
        # 没有找到注释
        return None
    
    # 清理和格式化注释文本
    comment_text = re.sub(r"\s+", " ", comment_text).strip()
    
    # 取第一句（以 . 或 @ 分隔）
    first_dot = comment_text.find(".")
    first_at = comment_text.find("@")
    
    # 修复取最小位置的逻辑
    valid_positions = [p for p in (first_dot, first_at) if p != -1]
    if valid_positions:
        cut_pos = min(valid_positions)
        comment_text = comment_text[:cut_pos].strip()
    
    return comment_text or None

# -- 主逻辑 ------------------------------------------------------------

def extract_functions(
    path: Path, *, with_comment: bool = False
) -> List[Dict[str, str]]:
    """从单个 .c 文件中提取函数(及可选注释)列表"""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        print(f"[warn] 跳过 {path}: {exc}", file=sys.stderr)
        return []

    records: List[Dict[str, str]] = []
    lines = text.splitlines()
    for match in FUNC_HEADER_RE.finditer(text):
        fn_name = match.group("name")
        if fn_name in C_KEYWORDS:
            continue
        body = slice_function_body(text, match.start())
        if not body:
            continue  # 跳过未闭合函数

        rec: Dict[str, str] = {
            "function_name": fn_name,
            "source_code": body,
        }
        
        # 总是提取函数，只是可选地添加注释
        if with_comment:
            # 计算行号
            def_line_idx = text.count("\n", 0, match.start())
            comment = preceding_block_comment(lines, def_line_idx)
            # 即使没有注释也保留函数，只是不添加comment字段
            rec["comment"] = comment if comment else ""
                
        records.append(rec)
    return records

# -- CLI ------------------------------------------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract C functions (and optionally comments) to JSON")
    p.add_argument("--project_root", default="/home/linjk/study/data/dataset/my_data/source", help="Root directory to scan for .c files")
    p.add_argument("--output_json", default="/home/linjk/study/data/result/test_src_info.json", help="Path to output JSON file")
    p.add_argument("--with-comment", action="store_true", dest="with_comment", help="Also extract block comments immediately above functions")
    return p.parse_args(argv)

# -- 入口 ------------------------------------------------------------

def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.project_root).expanduser().resolve()
    out = Path(args.output_json).expanduser().resolve()
    all_records: List[Dict[str, str]] = []

    for c_file in tqdm(find_c_files(root), desc="Scanning C files"):
        rel_project = c_file.relative_to(root).parts[0] if c_file != root else ""
        for rec in extract_functions(c_file, with_comment=args.with_comment):
            rec.update({"project_name": rel_project, "file_path": str(c_file)})
            all_records.append(rec)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(all_records, ensure_ascii=False, indent=4), encoding="utf-8")
    print(f"\n✅ 完成：共提取 {len(all_records)} 个函数 → {out}")

if __name__ == "__main__":
    main()
