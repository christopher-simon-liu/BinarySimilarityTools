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
#  ghidra_acfg_features.py                                                   #
#                                                                            #
#                                                                            #
##############################################################################

import bisect
import json
import ntpath
import os
import time

from ghidra.program.model.block import BasicBlockModel
from ghidra.app.util import XReferenceUtils
from ghidra.program.util import DefinedDataIterator
from ghidra.program.util import ProgramLocation

import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.bb_features import *
from core.ff_features import *

from collections import namedtuple

# setup utils
Utils = namedtuple(
  'Utils',
  ['addr_fact', 'fxn_manager', 'code_manager', 'ref_manager', 'code_block_model']
)

utils = Utils(
  currentProgram.getAddressFactory(),
  currentProgram.getFunctionManager(),
  currentProgram.getCodeManager(),
  currentProgram.getReferenceManager(),
  BasicBlockModel(currentProgram)
)

def ghidra_disassembly(bb):
    """Return basic-block mnemonics and normalized instructions."""
    try:
        bb_mnems, bb_norm = list(), list()

        for inst in utils.code_manager.getInstructions(bb, True):
            mnemonic = inst.getMnemonicString()
            bb_mnems.append(mnemonic)
            cinst = mnemonic
            for op_index in range(0, inst.getNumOperands()):
                op_str = inst.getDefaultOperandRepresentation(op_index)
                cinst += '_' + op_str
            bb_norm.append(cinst)

        return bb_mnems, bb_norm

    except Exception as e:
        print("[!] Ghidra exception", e)
        return list(), list()

def get_bb_features(bb, size, string_xrefs, arch):
    """Extract the features associated to a BB."""
    features_dict = dict()

    # Corner case
    if size == 0:
        features_dict = dict(
            bb_len=0,
            # BB list-type features
            bb_numerics=list(),
            bb_strings=list(),
            # BB numerical-type features
            n_numeric_consts=0,
            n_string_consts=0,
            n_instructions=0,
            n_arith_instrs=0,
            n_call_instrs=0,
            n_logic_instrs=0,
            n_transfer_instrs=0,
            n_redirect_instrs=0
        )
        return features_dict

    bb_mnems, bb_numerics = ghidra_disassembly(bb)

    # Get static strings from the BB
    bb_strings = set()
    addresses, entries = string_xrefs
    block_start = int(bb.getMinAddress().toString(), 16)
    block_end = int(bb.getMaxAddress().toString(), 16)
    start_index = bisect.bisect_left(addresses, block_start)
    end_index = bisect.bisect_right(addresses, block_end)
    for _, address, value in entries[start_index:end_index]:
        if bb.contains(address):
            bb_strings.add(value)
    
    features_dict = dict(
        bb_len=size,
        # BB list-type features
        bb_numerics=bb_numerics,
        bb_strings=list(bb_strings),
        # BB numerical-type features
        n_numeric_consts=len(bb_numerics),
        n_string_consts=len(bb_strings),
        n_instructions=len(bb_mnems),
        n_arith_instrs=get_n_arith_instrs(bb_mnems, arch),
        n_call_instrs=get_n_call_instrs(bb_mnems, arch),
        n_logic_instrs=get_n_logic_instrs(bb_mnems, arch),
        n_transfer_instrs=get_n_transfer_instrs(bb_mnems, arch),
        n_redirect_instrs=get_n_redirect_instrs(bb_mnems, arch)
    )
    return features_dict


def get_string_xref_index():
    """Build a sorted address index for fast basic-block string lookup."""
    entries = list()
    for string_ref in DefinedDataIterator.definedStrings(currentProgram):
        location = ProgramLocation(currentProgram, string_ref.getAddress())
        for xref in XReferenceUtils.getAllXrefs(location):
            address = xref.getFromAddress()
            entries.append((
                int(address.toString(), 16),
                address,
                string_ref.getValue()))
    entries.sort(key=lambda entry: entry[0])
    return [entry[0] for entry in entries], entries

def run_acfg_features(ghidra_proj_path, fva_list, output_dir):
    """Extract the features from each function. Save results to JSON."""
    print("[D] Processing: %s" % ghidra_proj_path)

    # Create output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_dict = dict()
    output_dict[ghidra_proj_path] = dict()

    procname = currentProgram.metadata['Processor']
    if procname == 'AARCH64':
        procname = 'ARM'
    bitness = int(currentProgram.metadata['Address Size'])
    output_dict[ghidra_proj_path]['arch'] = "{}-{}".format(procname, bitness)

    # Get the list of Strings for the ghidra project
    string_xrefs = get_string_xref_index()

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
                bbs_dict[start_address] = get_bb_features(
                    bb, size, string_xrefs, procname)
    
            # Function-level features
            function_features = get_function_features(
                fxn, fxn_addr, bbs_dict, len(edges_set), utils)
    
            elapsed_time = time.time() - start_time
    
            func_dict = {
                'nodes': list(nodes_set),
                'edges': list(edges_set),
                'features': function_features,
                'basic_blocks': bbs_dict,
                'elapsed_time': elapsed_time,
            }
            output_dict[ghidra_proj_path][hex(fva)] = func_dict

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    #print("[D] output_dict: {}".format(output_dict))
    out_name = ntpath.basename(ghidra_proj_path)+"_acfg_features.json"
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

    run_acfg_features(ghidra_proj_path, fva_list, output_dir)
