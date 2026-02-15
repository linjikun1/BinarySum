import idaapi
import idautils
import idc
import ida_hexrays
import ida_nalt
import ida_funcs
import json
import os
import re
from collections import defaultdict, Counter

# ----------------------------------------------------------------t
# Configuration & Globals
# ----------------------------------------------------------------t

# Minimum/Maximum word count to consider a function "interesting"
MIN_WORD_COUNT = 30
MAX_WORD_COUNT = 9192

# Segments to treat as external/imports
IMPORT_SEG_NAMES = {
    ".plt", ".plt.sec", ".got", ".got.plt",
    ".idata", ".idata$5", ".idata$6", ".idata$7",
    "__IMPORT", "__imp", "__plt"
}

# ----------------------------------------------------------------t
# Helpers
# ----------------------------------------------------------------t

def wait_auto():
    try:
        idaapi.auto_wait()
    except:
        pass

def word_count(code: str) -> int:
    tokens = re.findall(r"\w+|[^\s\w]", code)
    return len(tokens)

def get_decompiled_code(func_ea):
    try:
        cfunc = idaapi.decompile(func_ea)
        if cfunc:
            return str(cfunc)
    except Exception as e:
        pass
    return None

def is_external_api(func_ea: int, imported_eas: set) -> bool:
    if func_ea in imported_eas:
        return True
    seg_name = idc.get_segm_name(func_ea)
    if seg_name and seg_name.lower() in IMPORT_SEG_NAMES:
        return True
    # Heuristic: if decompilation is empty or just a JMP, treat as external
    try:
        decomp = str(idaapi.decompile(func_ea))
        if not decomp.strip():
            return True
        if idc.print_insn_mnem(func_ea).lower() == "jmp":
            return True
    except:
        pass
    return False

def is_noise_code(code: str, func_ea: int) -> bool:
    """Detects thunks, wrappers, or trivial functions."""
    if code.startswith("// attributes: thunk"):
        return True

    cleaned = re.sub(r"//.*?$", "", code, flags=re.M).strip()
    # Check for single-statement bodies like return f(...); or goto ...;
    m_body = re.search(r"\{(.*)\}", cleaned, flags=re.S)
    if m_body:
        body = m_body.group(1).strip()
        stmts = [s.strip() for s in body.split(';') if s.strip()]
        if len(stmts) == 1:
            if re.match(r"^(return\s+[^;]+|JUMPOUT\(.*\)|longjmp\(.*\)|setjmp\(.*\)|goto\s+\w+)$", stmts[0]):
                return True
            if stmts[0] == "return": # Empty return
                return True

    # Empty body
    if re.fullmatch(r".*\{\s*(;|return;)?\s*\}", cleaned, flags=re.S):
        return True

    # Check for extremely short assembly functions that just return
    func = idaapi.get_func(func_ea)
    if func and (func.end_ea - func.start_ea) <= 4:
        mnem = idc.print_insn_mnem(func.start_ea).lower()
        if mnem in {"ret", "retn"}:
            return True

    return False

# ----------------------------------------------------------------t
# CFG Extraction
# ----------------------------------------------------------------t

def build_cfg(func):
    cfg = {}
    try:
        fc = idaapi.FlowChart(func)
    except Exception as e:
        print(f"[WARN] FlowChart failed for {hex(func.start_ea)}: {e}")
        return cfg

    for block in fc:
        block_data = {
            "start_ea": block.start_ea,
            "end_ea": block.end_ea,
            "instructions": [],
            "successors": [succ.start_ea for succ in block.succs()],
            "predecessors": [pred.start_ea for pred in block.preds()]
        }
        for head in idautils.Heads(block.start_ea, block.end_ea):
            disasm = idc.GetDisasm(head)
            mnem = idc.print_insn_mnem(head)
            block_data["instructions"].append({
                "address": head,
                "mnemonic": mnem,
                "disassembly": disasm
            })
        cfg[block.start_ea] = block_data
    return cfg

# ----------------------------------------------------------------t
# CG Extraction (Improved)
# ----------------------------------------------------------------t

def collect_imports():
    imported_eas = set()
    try:
        mod_qty = ida_nalt.get_import_module_qty()
        for mod_idx in range(mod_qty):
            def _cb(ea, name, ordinal):
                imported_eas.add(ea)
                return True
            ida_nalt.enum_import_names(mod_idx, _cb)
    except Exception:
        pass
    return imported_eas

def extract_thunk_target(code: str):
    m = re.search(r"return\s+([A-Za-z_]\w*)\s*\(", code)
    return m.group(1) if m else None

def resolve_real_target(ea: int, max_depth: int = 5) -> int:
    """Resolves thunks to find the real target function."""
    visited = set()
    cur_ea = ea
    depth = 0
    while depth < max_depth and cur_ea not in visited:
        visited.add(cur_ea)
        func = idaapi.get_func(cur_ea)
        if not func: break
        
        try:
            code = str(idaapi.decompile(func.start_ea))
        except: break
        
        if not is_noise_code(code, cur_ea):
            break
            
        tgt_name = extract_thunk_target(code)
        if not tgt_name:
            break
        next_ea = idc.get_name_ea(idc.BADADDR, tgt_name)
        if next_ea == idc.BADADDR:
            break
        cur_ea = next_ea
        depth += 1
    return cur_ea

def _iter_call_targets(call_insn_ea: int):
    # 1) original: operand value
    op_type = idc.get_operand_type(call_insn_ea, 0)
    if op_type in (idc.o_near, idc.o_far, idc.o_mem):
        opnd_ea = idc.get_operand_value(call_insn_ea, 0)
        if opnd_ea != idc.BADADDR:
            yield opnd_ea

    # 2) fallback: direct xrefs
    for tgt in idautils.CodeRefsFrom(call_insn_ea, 0):
        yield tgt

def build_full_cg(func_info, noise_set, imported_eas):
    call_graph = defaultdict(set)
    call_counter = defaultdict(Counter)
    
    # Process all functions to build global call graph
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func: continue
        
        caller_name = idc.get_func_name(func_ea)
        # Skip noise functions as callers? Maybe not, better to track calls FROM noise too if needed.
        # But for 'func_info' we only care about non-noise targets.
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if not (mnem.startswith("call") or mnem.startswith("bl")):
                continue

            for opnd_ea in _iter_call_targets(head):
                callee_func = idaapi.get_func(opnd_ea)
                if not callee_func:
                    continue

                real_ea = resolve_real_target(callee_func.start_ea)
                real_name = idc.get_func_name(real_ea)
                
                if not real_name or is_external_api(real_ea, imported_eas):
                    continue

                # Record call (caller -> callee)
                # Store by ADDRESS or NAME? 
                # extract_cfg_cg.py used NAMES.
                # But pipeline.py uses ADDRESSES for uniqueness.
                # Let's use ADDRESSES as keys for robust matching.
                
                call_graph[func_ea].add(real_ea)
                call_counter[func_ea][real_ea] += 1
                
    # Invert for callers
    callers_map = defaultdict(set)
    for caller, callees in call_graph.items():
        for callee in callees:
            callers_map[callee].add(caller)
            
    return call_counter, callers_map

# ----------------------------------------------------------------t
# Main Extraction Logic
# ----------------------------------------------------------------t

def extract_all(output_path):
    wait_auto()
    
    if not idaapi.init_hexrays_plugin():
        print("[ERR] Hex-Rays decompiler not available.")
        return

    imported_eas = collect_imports()
    
    results = {}
    func_info = {} # ea -> code
    noise_set = set()
    
    print(f"[INFO] First pass: Decompiling functions from {idc.get_input_file_path()}...")
    
    # 1. Collect function info and noise set
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func: continue
        
        code = get_decompiled_code(func_ea)
        if not code: continue
        
        wc = word_count(code)
        if not (MIN_WORD_COUNT < wc < MAX_WORD_COUNT):
            continue
            
        func_info[func_ea] = code
        
        if is_noise_code(code, func_ea):
            noise_set.add(func_ea)
            
    # 2. Build global Call Graph
    print(f"[INFO] Building Call Graph...")
    call_counter, callers_map = build_full_cg(func_info, noise_set, imported_eas)
    
    # 3. Build final results
    print(f"[INFO] Extracting final data...")
    for func_ea, code in func_info.items():
        if func_ea in noise_set:
            continue
            
        func = idaapi.get_func(func_ea)
        func_name = idc.get_func_name(func_ea)
        
        # CFG
        cfg = build_cfg(func)
        
        # Prepare CG data
        # Callees
        my_callees_counts = call_counter[func_ea]
        # Callers
        my_callers_eas = callers_map.get(func_ea, [])
        my_callers_counts = {}
        for caller_ea in my_callers_eas:
            # How many times did caller call me?
            my_callers_counts[caller_ea] = call_counter[caller_ea][func_ea]
            
        # Format as expected by pipeline
        # Using EA as keys (strings)
        callees_dict = {str(ea): count for ea, count in my_callees_counts.items() if ea in func_info}
        callers_dict = {str(ea): count for ea, count in my_callers_counts.items() if ea in func_info}
        
        if not callees_dict and not callers_dict:
            # Optional: skip isolated functions if strict CG required
            # But usually we keep them if they have valid code/CFG
            pass

        results[func_ea] = {
            "function_name": func_name,
            "start_ea": func.start_ea,
            "end_ea": func.end_ea,
            "decompiled_code": code,
            "cfg": cfg,
            "callees": callees_dict,
            "callers": callers_dict,
            "word_count": word_count(code)
        }

    print(f"[INFO] Extracted {len(results)} functions.")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[INFO] Saved to {output_path}")

if __name__ == "__main__":
    out_file = os.environ.get("IDA_OUTPUT_FILE")
    if not out_file:
        import sys
        if len(idc.ARGV) > 1:
            out_file = idc.ARGV[1]
        else:
            print("[ERR] No output file specified via IDA_OUTPUT_FILE env var or argument.")
            idc.qexit(1)

    try:
        extract_all(out_file)
    except Exception as e:
        print(f"[ERR] Exception in extraction: {e}")
        import traceback
        traceback.print_exc()
        
    idc.qexit(0)
