##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  MIT License                                                               #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  Permission is hereby granted, free of charge, to any person obtaining     #
#  a copy of this software and associated documentation files (the           #
#  "Software"), to deal in the Software without restriction, including       #
#  without limitation the rights to use, copy, modify, merge, publish,       #
#  distribute, sublicense, and/or sell copies of the Software, and to        #
#  permit persons to whom the Software is furnished to do so, subject to     #
#  the following conditions:                                                 #
#                                                                            #
#  The above copyright notice and this permission notice shall be            #
#  included in all copies or substantial portions of the Software.           #
#                                                                            #
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,           #
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF        #
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                     #
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE    #
#  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION    #
#  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION     #
#  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.           #
#                                                                            #
#  IDA_flowchart.py - Extract BBs info using IDA's FlowChart APIs.           #
#                                                                            #
##############################################################################

import hashlib
import os
import time

from ghidra.program.model.block import BasicBlockModel

from collections import namedtuple

COLUMNS = [
    'ghidra_proj_path',
    'fva',
    'func_name',
    'start_ea',
    'end_ea',
    'bb_num',
    'bb_list',
    'hashopcodes']

BasicBlock = namedtuple('BasicBlock', ['va', 'size'])

# setup utils
Utils = namedtuple(
    'Utils',
    ['addr_fact', 'fxn_manager', 'code_manager', 'code_block_model']
)
 
utils = Utils(
    currentProgram.getAddressFactory(),
    currentProgram.getFunctionManager(),
    currentProgram.getCodeManager(),
    BasicBlockModel(currentProgram)
)

def string_to_hex(hex_str):
    return hex(int(hex_str, 16))

def get_function_end_addr(fxn):
    start_addr = fxn.getEntryPoint()
    # function body may include jumps outside to thunk functions, considered
    #   part of the function body
    main_fxn_body = [addr_range for addr_range in fxn.getBody().toList() if addr_range.contains(start_addr)][0]
    return main_fxn_body.getMaxAddress().toString()

def save_function_data(fxn, proj_path, proj_name, csv_out):
    try:
        func_name = fxn.getName(True)
        if "," in func_name:
            func_name = '"' + func_name + '"'
        # Get the list of basic-block addresses
        bb_sa_list = [block.getFirstStartAddress().toString() for block in 
                      utils.code_block_model.getCodeBlocksContaining(fxn.getBody(), monitor)]

        start_addr = fxn.getEntryPoint().toString()
        end_addr = get_function_end_addr(fxn)
        
        data = [os.path.join(proj_path, proj_name),
                string_to_hex(start_addr),
                func_name,
                string_to_hex(start_addr),
                string_to_hex(end_addr),
                len(bb_sa_list),
                ';'.join([str(string_to_hex(x)) for x in bb_sa_list]),
                hex(fxn.hashCode())]
        
        csv_out.write(','.join([str(x) for x in data]) + "\n")
    
    except Exception as e:
        print("[!] Exception: skipping function: {}".format(func_name))
        print(e)

def analyze_functions(proj_path, proj_name, output_csv):
    """
    Extract summary information from each function in the binary.

    Args:
        output_csv (str): path of the CSV file in output
    """
    start_time = time.time()
    
    # Write the result to the CSV
    csv_name = output_csv + "_" + proj_name + ".csv"
    print("[D] Output CSV: %s" % csv_name)
    
    with open(csv_name, 'w') as csv_out:
        csv_out.write(",".join(COLUMNS) + "\n")
            
        # For each function in the list
        for count, fxn in enumerate(utils.fxn_manager.getFunctions(True)):
            save_function_data(fxn, proj_path, proj_name, csv_out)
        
    print("[D] Processing %d functions took: %d seconds" %
          (count + 1, time.time() - start_time))
    return


if __name__ == "__main__":
    args = getScriptArgs()
    proj_path = args[0]
    proj_name = args[1]
    output_csv = args[2]

    analyze_functions(proj_path, proj_name, output_csv)
