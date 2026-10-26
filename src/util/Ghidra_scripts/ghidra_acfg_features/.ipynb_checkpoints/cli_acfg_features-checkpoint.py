#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
#  cli_acfg_features.py - Call IDA_acfg_features.py IDA script.              #
#                                                                            #
##############################################################################

import click
import json
import subprocess
import time
import ntpath
import multiprocessing
import traceback

from os import getenv
from os import makedirs
from os.path import abspath
from os.path import dirname
from os.path import isfile
from os.path import join
from os.path import isdir
from tqdm import tqdm
from collections import namedtuple

GHIDRA_PATH = getenv("GHIDRA_PATH", "/home/antonio/local/ghidra_11.0.3_PUBLIC/support/analyzeHeadless")
GHIDRA_SCRIPT_PATH = dirname(abspath(__file__))
GHIDRA_SCRIPT = 'ghidra_acfg_features.py'
REPO_PATH = dirname(dirname(dirname(abspath(__file__))))
LOG_PATH = "ghidra_acfg_features_log.txt"
SCRIPT_LOG_PATH = "acfg_features_log.txt"
TASK_LOG_DIR = 'acfg_features_logs'


CommonData = namedtuple(
    'CommonData',
    ['json_path', 'output_dir']
)

GhidraProjPaths = namedtuple(
    'GhidraProjPaths',
    ['full', 'relative']
)

Result = namedtuple(
    'Result',
    ['status_code', 'log']
)

COMMON_DATA = None

def task(ghidra_proj_path):
    cmd = [
            GHIDRA_PATH,
            dirname(ghidra_proj_path.relative),
            ntpath.basename(ghidra_proj_path.relative),
            '-scriptPath',
            GHIDRA_SCRIPT_PATH,
            '-postScript',
            GHIDRA_SCRIPT,
            COMMON_DATA.json_path,
            ghidra_proj_path.relative,
            COMMON_DATA.output_dir,
            '-process',
            ntpath.basename(ghidra_proj_path.relative),
            '-noanalysis',
            '-readonly'
    ]
    #print(f'{cmd} \nprocessing\n', flush=True)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return_status = 0
    
    if 'Error' in proc.stdout or 'error' in proc.stdout:
        with open(join(TASK_LOG_DIR, ntpath.basename(ghidra_proj_path.full)), 'w') as log:
            log.write(f'{cmd} \nprocessing\n')
            log.write(f'{proc.stdout}')
        print(f"[E] ERROR IN: {ntpath.basename(ghidra_proj_path.relative)}", flush=True)
        return_status = 1
        
    # 0 return success, else fail
    # Manually checking this, maybe a bad idea ¯\_(ツ)_/¯
    return return_status
    
def prepare_ghidra_proj_paths(rel_ghidra_proj_paths):
    #print("\n[D] Processing: {}".format(ghidra_proj_rel_path))

    # Convert the relative path into a full path
    ghidra_proj_paths = []
    for rel_path in rel_ghidra_proj_paths:
        full_path = join(REPO_PATH, rel_path)
        #print("[D] Ghidra proj full path: {}".format(ghidra_proj_path))

        if not isfile(full_path + '.gpr'):
            print("[!] Error: {} does not exist".format(full_path))
        else:
            ghidra_proj_paths.append(GhidraProjPaths(full_path, rel_path))
    
    return ghidra_proj_paths

@click.command()
@click.option('-j', '--json-path', required=True,
              help='JSON file with selected functions.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
@click.option('-b', '--batch-size', default=8,
              help='batch size for concurrent processes; default=8')
def main(json_path, output_dir, batch_size):
    """Call ghidra_acfg_features.py script."""
    global COMMON_DATA 
    COMMON_DATA = CommonData(json_path, output_dir)
    try:
        if not isfile(GHIDRA_PATH):
            print("[!] Error: GHIDRA_PATH:{} not valid".format(GHIDRA_PATH))
            print("Use 'export GHIDRA_PATH=/full/path/to/ghidra-analyzeHeadless'")
            return

        print("[D] JSON path: {}".format(json_path))
        print("[D] Output directory: {}".format(output_dir))

        if not isdir(TASK_LOG_DIR):
            makedirs(TASK_LOG_DIR)
        
        if not isfile(json_path):
            print("[!] Error: {} does not exist".format(json_path))
            return

        with open(json_path) as f_in:
            jj = json.load(f_in)

        success_cnt, error_cnt = 0, 0
        start_time = time.time()
        with multiprocessing.Pool(processes=batch_size) as pool:
            ghidra_proj_paths = prepare_ghidra_proj_paths(jj.keys())
            results = tqdm(pool.imap_unordered(task, ghidra_proj_paths), total=len(ghidra_proj_paths))

            for result in results:
                if result == 0:
                    success_cnt += 1
                else:
                    error_cnt += 1

        end_time = time.time()
        print("[D] Elapsed time: {}".format(end_time - start_time))
        with open(LOG_PATH, "a+") as f_out:
            f_out.write("elapsed_time: {}\n".format(end_time - start_time))

        print("\n# Ghidra projs correctly processed: {}".format(success_cnt))
        print("# Ghidra projs error: {}".format(error_cnt))

    except Exception as e:
        print("[!] Exception in cli_acfg_features\n{}".format(e))
        traceback.print_exc()


if __name__ == '__main__':
    main()
