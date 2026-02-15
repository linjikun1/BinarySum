import json
from tqdm import tqdm
from src.generator.summarizer_client import OpenAISummarizer

def _build_block_text(cfg: dict, blk_addr) -> str:
    """Helper to reconstruct assembly text for a block address."""
    block = cfg.get(str(blk_addr)) or cfg.get(blk_addr)
    if not block:
        return ""
    insts = [instr.get("disassembly", "") for instr in block.get("instructions", [])]
    insts = [x for x in insts if x]
    return "\n".join(insts)

def run_step2(input_path, output_path, config):
    """
    Step 2: Generate HPSS (Hierarchical Path-Sensitive Summary) using LLM.
    """
    print(f"[Step 2] Loading path data from {input_path}...")
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file {input_path} not found.")
        return

    summarizer = OpenAISummarizer(
        api_key=config['api_key'], 
        model_name=config['model_name'], 
        base_url=config['base_url']
    )

    all_time = 0.0
    all_cost = 0

    for item in tqdm(data, total=len(data), desc="Summarizing Paths (HPSS)"):
        cfg = item.get("cfg", {})
        paths = item.get("path", [])

        if not paths:
            item["path_summaries"] = {}
            item["cfg_summary"] = ""
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

        hpss_res = summarizer.generate_hpss_summary(hpss_paths, temperature=config.get('temperature', 0.5))

        if "error" in hpss_res:
            item["path_summaries"] = {}
            item["cfg_summary"] = ""
            item["hpss_error"] = hpss_res
        else:
            item["path_summaries"] = hpss_res.get("path_summaries", {})
            item["cfg_summary"] = (hpss_res.get("global_summary", "") or "").strip().strip('"')
            item["hpss_perf"] = hpss_res.get("perf", {})
            
            perf = item.get("hpss_perf", {})
            all_time += float(perf.get("duration", 0) or 0)
            all_cost += int(perf.get("tokens", 0) or 0)

    avg_time = all_time / len(data) if data else 0
    avg_cost = all_cost / len(data) if data else 0
    print(f"[Step 2] Stats - Avg Time: {avg_time:.2f}s, Avg Tokens: {avg_cost:.0f}")

    print(f"[Step 2] Saving HPSS summaries to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print("[Step 2] Done.")
