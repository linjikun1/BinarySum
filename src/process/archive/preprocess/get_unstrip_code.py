import sark
import pickle
import idc
import sys
import idaapi 
import ida_nalt
import json 
import os
import logging 

logging.basicConfig(level=logging.INFO,
                    filename='pseudo_unittest.log',
                    filemode='a',
                    format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

inputFileName = idc.get_input_file_path()
if os.path.exists("{}.unstrip_code.json".format(inputFileName)):
    idc.qexit(0)

logger.info(inputFileName)

if idc.get_idb_path().endswith('.i64'):
    cpu_width = 64
else:
    cpu_width = 32

text_segment = sark.Segment(name='.text')
try:
    if len(list(text_segment.functions)) == 0:
        idc.qexit(0)
except:
    idc.qexit(0)
    
if "vmlinux" in inputFileName:
    init_text_segment = sark.Segment(name=".init.text")
    exit_text_segment = sark.Segment(name=".exit.text")
else:
    init_text_segment = sark.Segment(name='.init')
    exit_text_segment = sark.Segment(name='.exit')

function_pseudo_map = {}
idaapi.auto_wait()
for function in text_segment.functions:
    try:
        logger.info("text segment Function {} at {}".format(function.name, function.ea))
        func = idaapi.get_func(function.start_ea)
        pseudo_code = idaapi.decompile(func.start_ea)
        if pseudo_code is None:
            logger.info(f"[-] Failed to decompile function at {hex(func.start_ea)}: code is None")
            continue
        pseudo_code = str(pseudo_code)
        function_pseudo_map[function.start_ea] = {
            'function_name': function.name,
            'decompiled_code': pseudo_code
        }
        # logger.warning(pseudo_code)
    except:
        logger.info("text segment error at function {}".format(function.name))
text_function_length = len(function_pseudo_map)
logger.info("text function length = {}".format(text_function_length))

try:
    for function in init_text_segment.functions:
        logger.info("init text segment Function {} at {}".format(function.name, function.ea))
        func = idaapi.get_func(function.start_ea)
        pseudo_code = idaapi.decompile(func.start_ea)
        if pseudo_code is None:
            logger.info(f"[-] Failed to decompile function at {hex(func.start_ea)}: code is None")
            continue
        pseudo_code = str(pseudo_code)
        function_pseudo_map[function.start_ea] = {
            'function_name': function.name,
            'decompiled_code': pseudo_code
        }
except:
    logger.warning("init function error.")
init_function_length = len(function_pseudo_map) - text_function_length
logger.info("init function length = {}".format(init_function_length))

try:
    for function in exit_text_segment.functions:
        logger.info("exit text segment Function {} at {}".format(function.name, function.ea))
        func = idaapi.get_func(function.start_ea)
        pseudo_code = idaapi.decompile(func.start_ea)
        if pseudo_code is None:
            logger.info(f"[-] Failed to decompile function at {hex(func.start_ea)}: code is None")
            continue
        pseudo_code = str(pseudo_code)
        function_pseudo_map[function.start_ea] = {
            'function_name': function.name,
            'decompiled_code': pseudo_code
        }
except:
    logger.warning("exit function error.")
exit_function_length = len(function_pseudo_map) - text_function_length - init_function_length
logger.info("exit function length = {}".format(exit_function_length))

with open("{}.unstrip_code.json".format(inputFileName), 'w') as file_obj:
    json.dump(function_pseudo_map, file_obj, indent=4)

idc.qexit(0)