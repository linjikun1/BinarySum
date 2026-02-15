import sark
import idc
import sys
import idaapi 
import idautils
import ida_hexrays
import json 
import os
import logging 
import ida_auto

logging.basicConfig(level=logging.INFO,
                    filename='pseudo_unittest.log',
                    filemode='w',
                    format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

inputFileName = idc.get_input_file_path()
if os.path.exists("{}.strip_code.json".format(inputFileName)):
    idc.qexit(0)
    
logger.info(inputFileName)

ida_auto.auto_wait()
function_pseudo_map = {}
for func_addr in idautils.Functions():
    try:
        func = idaapi.get_func(func_addr)
        strip_func_name = idc.get_func_name(func_addr)
        logger.info(strip_func_name)
        strip_pseudo_code = ida_hexrays.decompile(func.start_ea)
        if strip_pseudo_code is None:
            logger.info(f"[-] Failed to decompile function at {hex(func.start_ea)}: code is None")
            continue
        strip_pseudo_code = str(strip_pseudo_code)
        if strip_pseudo_code.startswith("// attributes: "):
            continue
        function_pseudo_map[func.start_ea] = {
            'strip_function_name': strip_func_name,
            'strip_decompiled_code': strip_pseudo_code
        }
    except Exception as e:
        logger.info(e)

logger.info("total function length = {}".format(len(function_pseudo_map)))

with open("{}.strip_code.json".format(inputFileName), 'w') as file_obj:
    json.dump(function_pseudo_map, file_obj, indent=4)

idc.qexit(0)

# /home/linjk/tools/ida-pro-9.0/idat -A -S"get_strip_code.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/binutils/addr2line.elf.elf