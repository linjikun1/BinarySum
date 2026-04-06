import json
from tqdm import tqdm
from src.generator.cfg_summarizer import OpenAISummarizer

def _build_block_text(cfg: dict, blk_addr) -> str:
    """Helper to reconstruct assembly text for a block address."""
    block = cfg.get(str(blk_addr)) or cfg.get(blk_addr)
    if not block:
        return ""
    insts = [instr.get("disassembly", "") for instr in block.get("instructions", [])]
    insts = [x for x in insts if x]
    return "\n".join(insts)

def generate_cfg_summaries(original_data_path, paths_path, output_path, config):
    """
    Generate CFG summaries (intermediate representation for HPSS).
    
    This function generates hierarchical path-sensitive summaries of CFGs,
    which serve as intermediate representation for final summary generation.
    
    Args:
        original_data_path: Path to original data JSON (contains cfg)
        paths_path: Path to paths JSON (from extract_cfg_paths)
        output_path: Output path for CFG summaries
        config: API configuration
    
    Output format: Only saves generated results (cfg_summary, path_summaries), not original data.
    """
    print(f"[generate_cfg_summaries] Loading original data from {original_data_path}...")
    try:
        with open(original_data_path, "r", encoding="utf-8") as f:
            original_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Original data file {original_data_path} not found.")
        return
    
    print(f"[generate_cfg_summaries] Loading paths from {paths_path}...")
    try:
        with open(paths_path, "r", encoding="utf-8") as f:
            paths_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Paths file {paths_path} not found.")
        return

    if len(original_data) != len(paths_data):
        print(f"Error: Data length mismatch! Original: {len(original_data)}, Paths: {len(paths_data)}")
        return

    summarizer = OpenAISummarizer(
        api_key=config['api_key'], 
        model_name=config['model_name'], 
        base_url=config['base_url']
    )

    all_time = 0.0
    all_cost = 0
    
    # Output: Only generated results
    results = []

    for orig_item, path_item in tqdm(zip(original_data, paths_data), total=len(original_data), desc="Summarizing Paths (HPSS)"):
        cfg = orig_item.get("cfg", {})
        paths = path_item.get("path", [])

        result = {
            'function_addr': orig_item.get('function_addr', ''),  # anchor for alignment check
        }
        
        if not paths:
            result['path_summaries'] = {}
            result['cfg_summary'] = ""
            results.append(result)
            continue

        blk_text_cache = {}
        hpss_paths = []
        for path in paths:
            path_blocks_text = []
            for blk_addr in path:
                if blk_addr not in blk_text_cache:
                    blk_text_cache[blk_addr] = _build_block_text(cfg, blk_addr)
                path_blocks_text.append(blk_text_cache[blk_addr])
            hpss_paths.append(path_blocks_text)

        hpss_res = summarizer.generate_hpss_summary(hpss_paths, temperature=config.get('temperature', 0.1))

        if "error" in hpss_res:
            result['path_summaries'] = {}
            result['cfg_summary'] = ""
            result['hpss_error'] = hpss_res
        else:
            result['path_summaries'] = hpss_res.get("path_summaries", {})
            result['cfg_summary'] = (hpss_res.get("global_summary", "") or "").strip().strip('"')
            result['hpss_perf'] = hpss_res.get("perf", {})
            
            perf = result.get('hpss_perf', {})
            all_time += float(perf.get("duration", 0) or 0)
            all_cost += int(perf.get("tokens", 0) or 0)
        
        results.append(result)

    avg_time = all_time / len(original_data) if original_data else 0
    avg_cost = all_cost / len(original_data) if original_data else 0
    print(f"[generate_cfg_summaries] Stats - Avg Time: {avg_time:.2f}s, Avg Tokens: {avg_cost:.0f}")

    print(f"[generate_cfg_summaries] Saving CFG summaries to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print("[generate_cfg_summaries] Done.")
