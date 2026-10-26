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
#  cli_flowchart.py - Call IDA_flowchart.py IDA script.                      #
#                                                                            #
##############################################################################

import click
import subprocess
import multiprocessing

from os import getcwd
from os import getenv
from os import walk
from os import listdir
from os import makedirs
from os.path import isdir
from os.path import abspath
from os.path import dirname
from os.path import isfile
from os.path import join
from os.path import relpath
from os.path import splitext

from tqdm import tqdm
from collections import namedtuple

GHIDRA_PATH = getenv("GHIDRA_PATH", "/home/antonio/local/ghidra_11.0.3_PUBLIC/support/analyzeHeadless")
GHIDRA_SCRIPT_PATH = dirname(abspath(__file__))
GHIDRA_SCRIPT = 'ghidra_flowchart.py'
REPO_PATH = dirname(dirname(dirname(abspath(__file__))))
LOG_PATH = "flowchart_log.txt"
TASK_LOG_DIR = 'flowchart_logs'

TaskArgs = namedtuple(
    'TaskArgs',
    ['ghidra_proj_path', 'ghidra_proj', 'output_csv']
)

def task(task_args):
    cmd = [GHIDRA_PATH,
           task_args.ghidra_proj_path,
           task_args.ghidra_proj,
           '-scriptPath',
           GHIDRA_SCRIPT_PATH,
           '-postScript',
           GHIDRA_SCRIPT,
           task_args.ghidra_proj_path,
           task_args.ghidra_proj,
           task_args.output_csv,
           '-process',
           task_args.ghidra_proj,
           '-noanalysis'
          ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return_status = 0
    
    if 'Error' in proc.stdout or 'error' in proc.stdout:
        with open(join(TASK_LOG_DIR, task_args.ghidra_proj), 'w') as log:
            log.write(f'{cmd} \nprocessing\n')
        print(f"[E] ERROR IN: {task_args.ghidra_proj}", flush=True)
        return_status = 1
    
    # 0 return success, else fail
    # Manually checking this, maybe a bad idea ¯\_(ツ)_/¯
    return return_status
        
@click.command()
@click.option("-p", "--ghidra-proj-folder", required=True, help="Path to the ghidra proj folder")
@click.option("-o", "--output-csv", required=True, help="Path to the output CSV file")
@click.option("-b", "--batch-size", default=8, help='batch size for concurrent processes; default=8')
def main(ghidra_proj_folder, output_csv, batch_size):
    """Call ghidra_flowchart.py script."""
    try:
        if not isfile(GHIDRA_PATH):
            print("[!] Error: GHIDRA_PATH:{} not valid".format(GHIDRA_PATH))
            print("Use 'export GHIDRA_PATH=/full/path/to/ghidra-analyzeHeadless'")
            return

        if not isdir(dirname(output_csv)):
            makedirs(dirname(output_csv))
        if not isdir('flowchart_logs'):
            makedirs('flowchart_logs')
        
        print("[D] ghidra proj folder: {}".format(ghidra_proj_folder))
        print("[D] Output CSV: {}".format(output_csv))

        ghidra_projs_task_args = [TaskArgs(root, splitext(f_name)[0], output_csv)
                                 for root, _, files in walk(ghidra_proj_folder)
                                 for f_name in files if f_name.endswith('.gpr')]
        success_cnt, error_cnt = 0, 0
        with multiprocessing.Pool(processes=batch_size) as pool:
            results = tqdm(pool.imap_unordered(task, ghidra_projs_task_args), total=len(ghidra_projs_task_args))

            for result in results:
                if result == 0:
                    success_cnt += 1
                else:
                    error_cnt += 1

        print("\n# ghidra projs correctly processed: {}".format(success_cnt))
        print("# ghidra projs error: {}".format(error_cnt))

    except Exception as e:
        print("[!] Exception in cli_flowchart\n{}".format(e))


if __name__ == '__main__':
    main()
