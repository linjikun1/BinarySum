import idc
import idautils
import idaapi
import ida_lines
import pickle
import sys
import ida_hexrays
import os
import json
import networkx as nx
sys.path.append(os.getcwd())
ida_hexrays.init_hexrays_plugin()

# SAVEROOT = "/home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/extracted-bins"  # dir of pickle files saved by IDA
# DATAROOT = "/home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/unstrip"  # dir of binaries (not stripped)
SAVEROOT = os.environ.get("SAVEROOT")
DATAROOT = os.environ.get("DATAROOT")

class BinaryData:

    def get_cfg(self, func):

        def get_attr(block, func_addr_set):
            asm, raw = [], b""
            curr_addr = block.start_ea
            if curr_addr not in func_addr_set:
                return -1
            # print(f"[*] cur: {hex(curr_addr)}, block_end: {hex(block.end_ea)}")
            while curr_addr <= block.end_ea:
                asm.append(idc.GetDisasm(curr_addr))
                raw += idc.get_bytes(curr_addr, idc.get_item_size(curr_addr))
                curr_addr = idc.next_head(curr_addr, block.end_ea)
            return asm, raw

        nx_graph = nx.DiGraph()
        flowchart = idaapi.FlowChart(
            idaapi.get_func(func), flags=idaapi.FC_PREDS)
        func_addr_set = set([addr for addr in idautils.FuncItems(func)])
        for block in flowchart:
            # Make sure all nodes are added (including edge-less nodes)
            attr = get_attr(block, func_addr_set)
            if attr == -1:
                continue
            nx_graph.add_node(block.start_ea, asm=attr[0], raw=attr[1])
            # print(f"[*] bb: {hex(block.start_ea)}, asm: {attr[0]}")
            for pred in block.preds():
                if pred.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(pred.start_ea, block.start_ea)
            for succ in block.succs():
                if succ.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(block.start_ea, succ.start_ea)
        return nx_graph

    def extract_all(self):
        for func_addr in idautils.Functions():
            if idc.get_segm_name(func_addr) in ['.plt', 'extern', '.init', '.fini']:
                continue
            cfg = self.get_cfg(func_addr)
            yield (func_addr, cfg)
            
if __name__ == "__main__":
    assert os.path.exists(DATAROOT), "DATAROOT does not exist"
    assert os.path.exists(SAVEROOT), "SAVEROOT does not exist"
    print("Current filename: %s" % idc.get_input_file_path())
    print("Absolute file path:", os.path.abspath(idc.get_input_file_path()))

    binary_path = idc.get_input_file_path()
    filename = os.path.basename(binary_path)
    strip_code_path = f"{binary_path}.strip_code.json"
    unstrip_code_path = os.path.join(os.path.dirname(binary_path), 'unstrip', filename + '.unstrip_code.json')
    unstrip_code_fixed_path = os.path.join(os.path.dirname(binary_path), 'unstrip', filename + '.unstrip_code_fixed.json')
    
    strip_addr_code_map = {}
    try:
        with open(strip_code_path, 'r') as f:
            strip_addr_code_map = json.load(f)
    except FileNotFoundError:
        print(f"Warning: {strip_code_path} not found. Using empty data.")
    addrs_for_cg = set(strip_addr_code_map.keys())
    addr_code_map_for_cg = {}
    for addr in addrs_for_cg:
        addr_code_map_for_cg[addr] = {
            'strip_function_name': strip_addr_code_map[addr]['strip_function_name'],
            'strip_decompiled_code': strip_addr_code_map[addr]['strip_decompiled_code'],
        }
    print(f"Match {len(addr_code_map_for_cg)} functions for addr_code_map_for_cg")

    unstrip_addr_code_map = {}
    unstrip_addr_code_fixed_map = {}
    try:
        with open(unstrip_code_path, 'r') as f:
            unstrip_addr_code_map = json.load(f)
    except FileNotFoundError:
        with open(unstrip_code_fixed_path, 'r') as f:
            unstrip_addr_code_fixed_map = json.load(f)
            unstrip_addr_code_map = unstrip_addr_code_fixed_map
            print(f"Instead, using fixed unstrip code map from {unstrip_code_fixed_path}")
    addrs = set(strip_addr_code_map.keys()) & set(unstrip_addr_code_map.keys())
    addr_code_map = {}
    for addr in addrs:
        addr_code_map[addr] = {
            'strip_function_name': strip_addr_code_map[addr]['strip_function_name'],
            'strip_decompiled_code': strip_addr_code_map[addr]['strip_decompiled_code'],
            'function_name': unstrip_addr_code_map[addr]['function_name'],
            'decompiled_code': unstrip_addr_code_map[addr]['decompiled_code'],
        }
    print(f"Match {len(addr_code_map)} functions for addr_code_map")

    idc.auto_wait()
    binary_data = BinaryData()

    saved_dict = {}
    saved_path = os.path.join(
        SAVEROOT, filename + "_extract.pkl")

    saved_dict_for_cg = {}
    saved_for_cg_path = os.path.join(
        SAVEROOT, filename + "_extract_cg.pkl")

    if os.path.exists(saved_path) and os.path.exists(saved_for_cg_path):
        print(f"File already exists, exiting IDA...")
        idc.qexit(0)

    with open(saved_path, 'wb') as f, open(saved_for_cg_path, 'wb') as f_cg:
        total_funcs = 0
        matched_funcs = 0
        for func_addr, cfg in binary_data.extract_all():
            total_funcs += 1
            if str(func_addr) in addr_code_map:
                matched_funcs += 1
                saved_dict[func_addr] = addr_code_map[str(func_addr)]
                saved_dict[func_addr]['cfg'] = cfg
            if str(func_addr) in addr_code_map_for_cg:
                saved_dict_for_cg[func_addr] = addr_code_map_for_cg[str(func_addr)]
                saved_dict_for_cg[func_addr]['cfg'] = cfg
        print(f"{matched_funcs} functions matched out of {total_funcs} total")
        pickle.dump(dict(saved_dict), f)
        pickle.dump(dict(saved_dict_for_cg), f_cg)
    idc.qexit(0)  # exit IDA