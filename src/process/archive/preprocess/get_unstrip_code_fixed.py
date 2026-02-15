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
if os.path.exists("{}.unstrip_code_fixed.json".format(inputFileName)):
    idc.qexit(0)

logger.info(inputFileName)

ida_auto.auto_wait()
function_pseudo_map = {}
for func_addr in idautils.Functions():
    try:
        func = idaapi.get_func(func_addr)
        func_name = idc.get_func_name(func_addr)
        logger.info(func_name)
        pseudo_code = ida_hexrays.decompile(func.start_ea)
        if pseudo_code is None:
            logger.info(f"[-] Failed to decompile function at {hex(func.start_ea)}: code is None")
            continue
        pseudo_code = str(pseudo_code)
        if pseudo_code.startswith("// attributes: "):
            continue
        function_pseudo_map[func.start_ea] = {
            'function_name': func_name,
            'decompiled_code': pseudo_code
        }
    except Exception as e:
        logger.info(e)

logger.info("total function length = {}".format(len(function_pseudo_map)))

with open("{}.unstrip_code_fixed.json".format(inputFileName), 'w') as file_obj:
    json.dump(function_pseudo_map, file_obj, indent=4)

idc.qexit(0)

# 某些二进制仅是not unstriped，但缺乏debug info，需要该脚本来获取函数的unstrip code
# /home/linjk/tools/ida-pro-9.0/idat -A -S"get_unstrip_code_fixed.py" /home/linjk/study/data/dataset/my_data/binary/x64_O2/cpulimit/unstrip/cpulimit.o.elf