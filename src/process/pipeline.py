#!/usr/bin/env python3
"""
Main pipeline script to process binaries and source code, match them, and generate datasets.

Usage:
    python pipeline.py --bin-dir <BINARY_DIR> --src-dir <SOURCE_DIR> --arch-opt <ARCH_OPT> --output-base <OUTPUT_BASE> --ida-path <IDAT_PATH>

Workflow:
1. Scan source directory and extract functions -> source.json
2. Scan binary directory, find stripped/unstripped pairs.
3. For each binary:
   - Run IDA on unstripped -> unstripped.json
   - Run IDA on stripped -> stripped.json
   - Merge info -> merged_bin.json
   - Run ProRec analysis (data dependency) -> data_for_ProRec
4. Match merged_bin.json with source.json -> final_dataset.json
5. Split and save for HexT5, BinT5, CP-BCS, ProRec.
"""

import argparse
import json
import os
import subprocess
import sys
import logging
from pathlib import Path
from tqdm import tqdm
import re
import pickle
import gzip
import networkx as nx

# Add lib directory to path for analysis modules
lib_dir = Path(__file__).parent / "lib"
sys.path.append(str(lib_dir))

try:
    from lib.analysis.expr_lang_analyzer import ExprLangAnalyzer
except ImportError:
    print(f"Warning: Could not import ExprLangAnalyzer from {lib_dir}. ProRec features will be skipped.")
    ExprLangAnalyzer = None

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_ida_script(ida_path, script_path, binary_path, output_path):
    """Runs an IDA script on a binary."""
    env = os.environ.copy()
    env["IDA_OUTPUT_FILE"] = str(output_path)
    
    cmd = [ida_path, "-A", f"-S{script_path}", str(binary_path)]
    
    try:
        # Capture output to avoid clutter, unless debug
        result = subprocess.run(cmd, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"IDA failed for {binary_path}: {e.stderr}")
        return False

def extract_source(src_dir, output_json, script_path):
    """Runs the source extraction script."""
    cmd = [sys.executable, script_path, "--project_root", str(src_dir), "--output_json", str(output_json), "--with-comment"]
    subprocess.run(cmd, check=True)

def word_count(code: str) -> int:
    tokens = re.findall(r"\w+|[^\s\w]", code)
    return len(tokens)

def build_nx_graph(cfg_data):
    """Converts JSON CFG to NetworkX DiGraph for analysis."""
    G = nx.DiGraph()
    for addr_str, block in cfg_data.items():
        addr = int(addr_str)
        # Extract instructions list (disassembly strings)
        instrs = [i['disassembly'] for i in block['instructions']]
        G.add_node(addr, asm=instrs)
        
        # Add edges
        for succ in block['successors']:
            G.add_edge(addr, succ)
    return G

def run_prorec_analysis(cfg_data, strip_func_name, strip_decompiled_code):
    """Runs data dependency analysis for ProRec."""
    if not ExprLangAnalyzer:
        return None, None
        
    try:
        cfg_graph = build_nx_graph(cfg_data)
        analyzer = ExprLangAnalyzer(cfg_graph)
        
        # Extract features
        instr_strs, deps_strs = analyzer._build_instrs_and_deps()
        
        data_for_ProRec = {
            'strip_function_name': strip_func_name,
            'strip_decompiled_code': strip_decompiled_code,
            'code': instr_strs,
            'data_dep': deps_strs
        }
        
        # Also return flat asm code (list of strings)
        # The analyzer logic usually gets normalized code, but we can return raw for now or adapt
        # For compatibility with old asm_code, we might want the raw instructions
        asm_code = []
        for addr in sorted(cfg_graph.nodes):
            asm_code.extend(cfg_graph.nodes[addr]['asm'])
            
        return data_for_ProRec, asm_code
        
    except Exception as e:
        logger.warning(f"ProRec analysis failed: {e}")
        return None, None

def match_bin_source(bin_data, src_data):
    """
    Matches binary functions to source functions.
    Strategy: 
    1. Match by exact function name (available from unstripped binary analysis).
    2. Filter by word count similarity.
    """
    matched = []
    
    # Index source by (project, function_name)
    src_index = {}
    for item in src_data:
        # Normalize project name if needed (e.g. remove -src suffix)
        proj = item.get("project_name", "").split("-")[0]
        func = item.get("function_name", "")
        src_index[(proj, func)] = item
    
    # Iterate binary data
    for bin_func in bin_data:
        proj = bin_func.get("project_name", "").split("-")[0]
        # The unstripped analysis gives us the real function name
        real_name = bin_func.get("function_name", "")
        
        src_item = src_index.get((proj, real_name))
            
        # Optional: content filtering
        decomp_code = bin_func.get("decompiled_code", "")
        src_code = src_item.get("source_code", "") if src_item else None
        
        wc_decomp = word_count(decomp_code)
        wc_src = word_count(src_code) if src_code else 0
        
        # Basic sanity check
        if not (30 < wc_decomp < 9192):
            continue
            
        # If source matching is required (i.e. src_data is provided), filter by source code size too
        if src_data and not src_item:
            # Skip if source data was provided but no match found
            continue
            
        if src_item and not (30 < wc_src < 9192):
            continue
            
        # Combine data
        matched.append({
            **bin_func, # Contains binary info (CFG, CG, asm, decompiled)
            "source_code": src_code,
            "comment": src_item.get("comment", "") if src_item else None
        })
        
    return matched

def save_split_datasets(final_dataset, output_dir):
    """Splits and saves datasets for different downstream tasks."""
    
    result_baseline = []
    result_dataset = []
    
    # -------------------------------------------------------------------------
    # [Pre-compute Global CodeArt Lookup]
    # To enrich CG data (callers/callees) with codeart features, we first build
    # a lookup table of ALL functions available in the dataset.
    # Key: function_addr (int) or (proj, strip_name, code_prefix)
    # The old convert.py used (proj, strip_name, code_prefix) but addr is safer if unique per binary.
    # Since we merged everything into one list, address collisions across binaries are possible.
    # So we use (project_name, function_addr) as unique key.
    # -------------------------------------------------------------------------
    
    # Map: (project_name, function_addr) -> {code, data_dep}
    addr_lookup = {}
    
    # Also support name-based lookup for compatibility if callees keys are names?
    # No, IDA extract script uses ADDRESSES as keys for callees.
    # So we strictly use address matching.
    
    for rec in final_dataset:
        proj = rec['project_name']
        addr = rec['function_addr']
        meta = rec.get('data_for_ProRec')
        
        if meta:
            addr_lookup[(proj, addr)] = {
                'code': meta.get('code'),
                'data_dep': meta.get('data_dep')
            }

    for rec in final_dataset:
        proj = rec['project_name']
        strip_name = rec['strip_function_name']
        
        # 1. Baseline Item (BinT5, HexT5, CPBCS, ProRec)
        baseline_item = rec.copy()
        
        # Add aliases for CP-BCS / MiSum
        baseline_item['function_name_in_strip'] = strip_name
        baseline_item['function_body'] = rec.get('asm_code')
        baseline_item['pseudo_code'] = rec['strip_decompiled_code']
        baseline_item['pseudo_code_non_strip'] = rec['decompiled_code']
        baseline_item['pseudo_code_refined'] = rec['strip_decompiled_code']
        
        # Add aliases for ProRec (Self CodeArt)
        # This is already in 'data_for_ProRec', aliased to 'meta'
        baseline_item['meta'] = rec.get('data_for_ProRec')
        
        result_baseline.append(baseline_item)
        
        # 2. Dataset Item (CFG + CG + Metadata)
        # Needs to enrich callees with codeart info
        
        # 1. Enrich Callees
        # Extract raw callees (format: {addr_str: count})
        raw_callees = rec.get('callees', {})
        enriched_callees = {}
        
        if raw_callees:
            for callee_addr_str, count in raw_callees.items():
                try:
                    callee_addr = int(callee_addr_str)
                except ValueError:
                    continue
                    
                # Look up codeart info (strict address match)
                callee_info = addr_lookup.get((proj, callee_addr))
                if callee_info:
                    enriched_callees[str(callee_addr)] = {
                        'code': callee_info['code'],
                        'data_dep': callee_info['data_dep']
                    }
                    
        # 2. Enrich Callers (New)
        # Extract raw callers (format: {addr_str: count})
        raw_callers = rec.get('callers', {})
        enriched_callers = {}
        
        if raw_callers:
            for caller_addr_str, count in raw_callers.items():
                try:
                    caller_addr = int(caller_addr_str)
                except ValueError:
                    continue
                    
                # Look up codeart info (strict address match)
                caller_info = addr_lookup.get((proj, caller_addr))
                if caller_info:
                    enriched_callers[str(caller_addr)] = {
                        'code': caller_info['code'],
                        'data_dep': caller_info['data_dep']
                    }
        
        dataset_item = {
            'project_name': proj,
            'function_addr': rec['function_addr'],
            'strip_function_name': strip_name,
            'strip_decompiled_code': rec['strip_decompiled_code'],
            'source_code': rec.get('source_code'),
            'comment': rec.get('comment'),
            'cfg': rec['cfg'],
            # Self CodeArt
            'codeart': rec.get('data_for_ProRec'), 
            # Enriched Callers & Callees
            'callers': enriched_callers,
            'callees': enriched_callees
        }
        result_dataset.append(dataset_item)

    # Save files
    tasks = {
        "baseline": result_baseline,
        "dataset": result_dataset
    }
    
    for task_name, data in tasks.items():
        out_path = output_dir / f"{task_name}.pkl.gz"
        logger.info(f"Saving {task_name} dataset to {out_path} ({len(data)} items)...")
        with gzip.open(out_path, 'wb') as f:
            pickle.dump(data, f)


def run_pipeline(args):
    bin_dir = Path(args.bin_dir) / args.arch_opt
    src_dir = Path(args.src_dir) if args.src_dir else None
    
    # Construct output directory: process/tmpresult/<arch_opt>
    out_dir = Path(args.output_dir) / args.arch_opt
    out_dir.mkdir(parents=True, exist_ok=True)
    
    scripts_dir = Path(__file__).parent / "scripts"
    ida_script = scripts_dir / "ida_extract.py"
    src_script = scripts_dir / "src_extract.py"
    
    # 1. Extract Source Info
    source_json = Path(args.output_dir) / "source_info.json"
    src_data = []
    
    if src_dir:
        if not source_json.exists():
            logger.info("Extracting source info...")
            extract_source(src_dir, source_json, src_script)
        else:
            logger.info("Source info already exists, skipping.")
            
        with open(source_json, "r") as f:
            src_data = json.load(f)
    else:
        logger.warning("No source directory provided. Source matching will be skipped.")
        
    # 2. Process Binaries
    # We expect structure: bin_dir/project/*.elf and bin_dir/project/unstrip/*.elf
    if not bin_dir.exists():
        logger.error(f"Binary directory {bin_dir} does not exist.")
        sys.exit(1)
        
    projects = [p for p in bin_dir.iterdir() if p.is_dir()]
    
    all_bin_data = []
    
    for project in tqdm(projects, desc="Processing Projects"):
        project_name = project.name
        # Find stripped ELFs (exclude unstrip folder itself)
        elfs = [f for f in project.glob("*.elf") if f.is_file()]
        
        for elf in elfs:
            # Check for corresponding unstripped
            # Expect unstrip located at: project/unstrip/elf.name
            unstrip_elf = project / "unstrip" / elf.name
            if not unstrip_elf.exists():
                # Try finding without .elf extension or other variations if needed
                # But for now assume strict naming
                logger.warning(f"No unstripped binary found for {unstrip_elf}, skipping.")
                continue
                
            # Define output paths (intermediate results stay in out_dir/intermediate)
            res_dir = out_dir / "intermediate" / project_name
            res_dir.mkdir(parents=True, exist_ok=True)
            
            strip_json = res_dir / f"{elf.name}.stripped.json"
            unstrip_json = res_dir / f"{elf.name}.unstripped.json"
            
            # Run IDA
            if not strip_json.exists():
                logger.info(f"Processing stripped: {elf.name}")
                if not run_ida_script(args.ida_path, ida_script, elf, strip_json):
                    continue
            
            if not unstrip_json.exists():
                logger.info(f"Processing unstripped: {elf.name}")
                if not run_ida_script(args.ida_path, ida_script, unstrip_elf, unstrip_json):
                    continue
                    
            # Merge
            try:
                with open(strip_json) as f: s_data = json.load(f)
                with open(unstrip_json) as f: u_data = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load JSONs for {elf.name}: {e}")
                continue
            
            # Match by EA (assuming 1:1 mapping at function start addresses, which is usually true for simple strip)
            
            for ea_str, s_func in s_data.items():
                u_func = u_data.get(ea_str)
                if not u_func:
                    continue
                
                # Perform ProRec analysis
                data_for_ProRec, asm_code = run_prorec_analysis(
                    s_func["cfg"], 
                    s_func["function_name"], 
                    s_func["decompiled_code"]
                )
                
                merged_entry = {
                    "project_name": project_name,
                    "binary_name": elf.name,
                    "function_addr": int(ea_str),
                    "strip_function_name": s_func["function_name"],
                    "function_name": u_func["function_name"],
                    "strip_decompiled_code": s_func["decompiled_code"],
                    "decompiled_code": u_func["decompiled_code"],
                    "cfg": s_func["cfg"], # Use stripped CFG
                    "callees": s_func.get("callees", {}), # Use stripped Call Graph
                    "callers": s_func.get("callers", {}), # Use stripped Call Graph (Callers)
                    "asm_code": asm_code,
                    "data_for_ProRec": data_for_ProRec
                }
                all_bin_data.append(merged_entry)
                
    # 3. Match Binary & Source
    if src_data:
        logger.info("Matching binary and source data...")
        final_dataset = match_bin_source(all_bin_data, src_data)
    else:
        logger.info("Skipping source matching (no source data). Saving binary info only.")
        final_dataset = all_bin_data
    
    # 4. Save Final Results
    logger.info(f"Saving final dataset with {len(final_dataset)} entries to {out_dir}...")
    
    # Save master dataset (readable json)
    with open(out_dir / "dataset.json", "w") as f:
        json.dump(final_dataset, f, indent=2)
    
    # 5. Save Splits (baseline, dataset)
    logger.info("Saving datasets (baseline, dataset)...")
    save_split_datasets(final_dataset, out_dir)
        
    logger.info("Done!")

def main():
    parser = argparse.ArgumentParser(description="Binary Analysis Pipeline")
    parser.add_argument("--bin-dir", default="/data/linjk/data/binary", help="Directory containing binaries for specific arch (e.g. bindata/x64_O3)")
    parser.add_argument("--src-dir", default="/data/linjk/data/source", help="Directory containing source code")
    parser.add_argument("--arch-opt", required=True, help="Architecture and optimization level (e.g. x64_O3). Used for output folder naming.")
    parser.add_argument("--output-dir", default="/data/linjk/process/result", help="Base directory for output data")
    parser.add_argument("--ida-path", default="/data/tool/ida-pro-9.1/idat", help="Path to IDA Pro executable (idat)")
    
    args = parser.parse_args()
    run_pipeline(args)
    
if __name__ == "__main__":
    main()
