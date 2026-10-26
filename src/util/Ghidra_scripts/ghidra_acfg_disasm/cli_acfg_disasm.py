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
#  cli_acfg_disasm.py - Call ghidra_acfg_disasm.py script.                   #
#                                                                            #
##############################################################################

import click
import json
import subprocess
import time
import ntpath

from os import getenv
from os import makedirs
from os import remove
from os.path import abspath
from os.path import dirname
from os.path import isfile
from os.path import join

GHIDRA_SCRIPT_PATH = dirname(abspath(__file__))
GHIDRA_SCRIPT = 'ghidra_acfg_disasm.py'
SOURCE_PATH = dirname(dirname(dirname(dirname(abspath(__file__)))))
REPO_PATH = dirname(SOURCE_PATH)
GHIDRA_PATH = getenv(
    "GHIDRA_PATH",
    join(SOURCE_PATH, "util", "ghidra", "support", "analyzeHeadless"))
LOG_PATH = "ghidra_acfg_disasm_log.txt"
SCRIPT_LOG_PATH = "acfg_disasm_log.txt"


@click.command()
@click.option('-j', '--json-path', required=True, help='JSON file with selected functions.')
@click.option('-o', '--output-dir', required=True, help='Output directory.')
def main(json_path, output_dir):
    """Call ghidra_acfg_disasm.py script."""
    try:
        if not isfile(GHIDRA_PATH):
            raise click.ClickException(
                "GHIDRA_PATH is not valid: {}".format(GHIDRA_PATH))

        json_path = abspath(json_path)
        output_dir = abspath(output_dir)
        makedirs(output_dir, exist_ok=True)
        print("[D] JSON path: {}".format(json_path))
        print("[D] Output directory: {}".format(output_dir))

        if not isfile(json_path):
            raise click.ClickException("{} does not exist".format(json_path))

        ghidra_log_path = join(output_dir, LOG_PATH)
        script_log_path = join(output_dir, SCRIPT_LOG_PATH)

        with open(json_path) as f_in:
            jj = json.load(f_in)

        success_cnt, error_cnt = 0, 0
        start_time = time.time()
        for ghidra_proj_rel_path in jj.keys():
            print("\n[D] Processing: {}".format(ghidra_proj_rel_path))

            # Convert the relative path into a full path
            ghidra_proj_path = join(REPO_PATH, ghidra_proj_rel_path)
            print("[D] Ghidra proj full path: {}".format(ghidra_proj_path))

            if not isfile(ghidra_proj_path+'.gpr'):
                print("[!] Error: {} does not exist".format(ghidra_proj_path))
                error_cnt += 1
                continue

            output_path = join(
                output_dir,
                ntpath.basename(ghidra_proj_rel_path) + '_acfg_disasm.json')
            if isfile(output_path):
                remove(output_path)

            cmd = [GHIDRA_PATH,
                   dirname(ghidra_proj_path),
                   ntpath.basename(ghidra_proj_rel_path),
                   '-scriptPath',
                   GHIDRA_SCRIPT_PATH,
                   '-postScript',
                   GHIDRA_SCRIPT,
                   json_path,
                   ghidra_proj_rel_path,
                   output_dir,
                   '-process',
                   ntpath.basename(ghidra_proj_rel_path),
                   '-noanalysis',
                   '-readonly',
                   '-log',
                   ghidra_log_path
                  ]

            print("[D] cmd: {}".format(cmd))

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate()
            with open(script_log_path, 'a') as log_file:
                log_file.write(stdout)
                log_file.write(stderr)

            if proc.returncode == 0 and isfile(output_path):
                print("[D] {}: success".format(ghidra_proj_path))
                success_cnt += 1
            else:
                print("[!] Error in {} (returncode={})".format(
                    ghidra_proj_path, proc.returncode))
                error_cnt += 1

        end_time = time.time()
        print("[D] Elapsed time: {}".format(end_time - start_time))
        with open(ghidra_log_path, "a+") as f_out:
            f_out.write("elapsed_time: {}\n".format(end_time - start_time))
        
        print("\n# Ghidra projs correctly processed: {}".format(success_cnt))
        print("# Ghidra projs error: {}".format(error_cnt))
        if error_cnt:
            raise click.ClickException(
                "failed to process {} Ghidra project(s)".format(error_cnt))

    except Exception as e:
        if isinstance(e, click.ClickException):
            raise
        raise click.ClickException("ACFG disassembly failed: {}".format(e))


if __name__ == '__main__':
    main()
