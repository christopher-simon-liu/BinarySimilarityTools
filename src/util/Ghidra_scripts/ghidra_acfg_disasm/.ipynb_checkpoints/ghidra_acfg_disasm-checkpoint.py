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
#  Ghidra_acfg_disasm.py - acfg_disasm IDA plugin implementation.            #
#                                                                            #
#  This plugin contains code from:                                           #
#  github.com/williballenthin/python-idb/ licensed under Apache License 2.0  #
#                                                                            #
##############################################################################

import base64
import json
import ntpath
import os
import time

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.lang import OperandType

from collections import namedtuple
import codecs

BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs'])


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

def convert_procname_to_str(procname, bitness):
    """Convert the arch and bitness to a std. format."""
    if procname == 'mipsb':
        return "mips-{}".format(bitness)
    if procname == "arm":
        return "arm-{}".format(bitness)
    if "pc" in procname:
        return "x86-{}".format(bitness)
    raise RuntimeError(
        "[!] Arch not supported ({}, {})".format(
            procname, bitness))

def get_prefix(procname):
    prefix = "UNK_"

    # WARNING: mipsl mode not supported here
    if procname == 'mipsb':
        prefix = "M_"
    if procname == "arm":
        prefix = "A_"
    if "pc" in procname:
        prefix = "X_"
    return prefix

def get_bytes_and_addr(inst):
    hex_str = ''
    for byte in inst.getBytes():
        if byte > 0:
            hex_str += '{:02x}'.format(byte)
        else:
            hex_str += '{:02x}'.format(byte & 0xff)
    data = codecs.decode(hex_str, 'hex')
    addr_str = inst.getAddress().toString()
    addr = int(addr_str, 16)
    return data, addr

def ghidra_disassembly(bb, prefix):
    """Return the BB (normalized) disassembly, with mnemonics and BB heads."""
    try:
        bb_heads, bb_mnems, bb_disasm, bb_norm = list(), list(), list(), list()

        # Iterate over each instruction in the BB
        for inst in utils.code_manager.getInstructions(bb, True):
            data, addr = get_bytes_and_addr(inst)
            mnemonic = inst.getMnemonicString()
            # Get the address
            bb_heads.append(addr)
            # Get the mnemonic
            bb_mnems.append(mnemonic)
            # Get the disasm
            bb_disasm.append(inst.toString())

            # Compute the normalized code. Ignore the prefix.
            # cinst = prefix + i_inst.mnemonic
            cinst = mnemonic

            # Iterate over the operands
            for op_index in range(0, inst.getNumOperands()):
                op = inst.getOpObjects(op_index)
                op_type = inst.getOperandType(op_index)
                op_type_str = OperandType().toString(inst.getOperandType(op_index))
                op_str = inst.getDefaultOperandRepresentation(op_index)

                cinst += '_' + op_str
            bb_norm.append(cinst)

        return bb_heads, bb_mnems, bb_disasm, bb_norm

    except Exception as e:
        print("[!] Ghidra exception", e)
        return list(), list(), list(), list()

def get_bb_disasm(bb, prefix):
    """Return the (nomalized) disassembly for a BasicBlock."""
    bb_data = ''
    for inst in utils.code_manager.getInstructions(bb, True):
        data, _ = get_bytes_and_addr(inst)
        bb_data += data
    b64_bytes = base64.b64encode(bb_data)
    bb_heads, bb_mnems, bb_disasm, bb_norm = \
        ghidra_disassembly(bb, prefix)
    return b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm


def run_acfg_disasm(ghidra_proj_path, fva_list, output_dir):
    """Disassemble each function. Extract the CFG. Save output to JSON."""
    print("[D] Processing: %s" % ghidra_proj_path)

    # Create output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_dict = dict()
    output_dict[ghidra_proj_path] = dict()

    procname = currentProgram.metadata['Processor'].lower()
    bitness = int(currentProgram.metadata['Address Size'])
    prefix = get_prefix(procname)
    output_dict[ghidra_proj_path]['arch'] = "{}-{}".format(procname, bitness)

    # Iterate over each function
    for fva in fva_list:
        try:
            start_time = time.time()
            fxn_addr = utils.addr_fact.getAddress(hex(fva))
            fxn = utils.fxn_manager.getFunctionAt(fxn_addr)
            nodes_set, edges_set = set(), set()
            bbs_dict = dict()
            for bb in utils.code_block_model.getCodeBlocksContaining(fxn.getBody(), monitor):
                # CFG
                start_address = int(bb.getFirstStartAddress().toString(), 16)
                size = bb.getNumAddresses()
                nodes_set.add(start_address)
                dests = bb.getDestinations(monitor)
                while dests.hasNext():
                    dest = dests.next()
                    dest_address = int(dest.getDestinationAddress().toString(), 16)
                    edges_set.add((start_address, dest_address))
                # BB-level features
                if size:
                    b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = \
                        get_bb_disasm(bb, prefix)
                    bbs_dict[start_address] = {
                        'bb_len': size,
                        'b64_bytes': b64_bytes,
                        'bb_heads': bb_heads,
                        'bb_mnems': bb_mnems,
                        'bb_disasm': bb_disasm,
                        'bb_norm': bb_norm
                    }
                else:
                    bbs_dict[start_address] = {
                        'bb_len': size,
                        'b64_bytes': "",
                        'bb_heads': list(),
                        'bb_mnems': list(),
                        'bb_disasm': list(),
                        'bb_norm': list()
                    }
            elapsed_time = time.time() - start_time
            func_dict = {
                'nodes': list(nodes_set),
                'edges': list(edges_set),
                'elapsed_time': elapsed_time,
                'basic_blocks': bbs_dict
            }
            output_dict[ghidra_proj_path][hex(fva)] = func_dict

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    out_name = ntpath.basename(ghidra_proj_path)+"_acfg_disasm.json"
    with open(os.path.join(output_dir, out_name), "w") as f_out:
        json.dump(output_dict, f_out)


if __name__ == '__main__':
    args = getScriptArgs()
    input_json = args[0]
    ghidra_proj_path = args[1]
    output_dir = args[2]
    
    with open(input_json) as f_in:
        selected_functions = json.load(f_in)

    if ghidra_proj_path not in selected_functions:
        print("[!] Error! Ghidra proj path (%s) not in %s" % (ghidra_proj_path, input_json))
        exit(1)

    fva_list = selected_functions[ghidra_proj_path]
    print("[D] Found %d addresses" % len(fva_list))

    run_acfg_disasm(ghidra_proj_path, fva_list, output_dir)
