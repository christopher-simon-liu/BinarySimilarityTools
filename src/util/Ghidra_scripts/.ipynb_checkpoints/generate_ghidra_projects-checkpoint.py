#!/usr/bin/env python
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
#  generate_ghidra_projs.py -                                                #
#    Analyse the binary with Ghidra and save the project                     #
#                                                                            #
##############################################################################

import click
import subprocess

from os import getenv
from os import makedirs
from os import mkdir
from os import walk
from os.path import abspath
from os.path import dirname
from os.path import isdir
from os.path import isfile
from os.path import join
from os.path import relpath
from os.path import samefile


BIN_FOLDER = join(dirname(dirname(abspath(__file__))), 'Binaries')
GHIDRA_PROJ_FOLDER = join(dirname(dirname(abspath(__file__))), 'GhidraProjs')

GHIDRA_PATH = getenv("GHIDRA_PATH", "/home/antonio/local/ghidra_11.0.3_PUBLIC/support/analyzeHeadless")

LOG_PATH = "generate_ghidra_proj_log.txt"

TEST_BINARIES = {
    "nmap/arm32-clang-5.0-O0_ncat": "arm32-clang-5.0-O0_ncat",
    "openssl/arm32-clang-3.5-O0_libcrypto.so.3": "arm32-clang-3.5-O0_libcrypto.so.3",
    "zlib/arm32-clang-3.5-O0_libz.so.1.2.11": "arm32-clang-3.5-O0_libz.so.1.2.11",
    "zlib/arm64-clang-9-O0_minigzipsh": "arm64-clang-9-O0_minigzipsh",
    "zlib/arm64-clang-9-O2_minigzipsh": "arm64-clang-9-O2_minigzipsh",
    "curl/arm32-clang-3.5-O0_curl": "arm32-clang-3.5-O0_curl",
    "curl/arm32-clang-9-O1_curl": "arm32-clang-9-O1_curl",
    "unrar/arm32-clang-5.0-O0_unrar": "arm32-clang-5.0-O0_unrar",
    "unrar/arm32-gcc-5-O0_unrar": "arm32-gcc-5-O0_unrar"
}


def ghidra_analyze(proj_folder, proj_name, bin_path):
    """Launch Ghidra and analyze binaries. Inner function."""
    try:
        print("Ghidra analyze for {}".format(bin_path))
        ghidra_output = str(subprocess.check_output([
            GHIDRA_PATH,
            proj_folder,
            proj_name,
            "-log",
            LOG_PATH,  # name of the log file.
            "-import",
            bin_path
        ]))

        expected_ghidra_file = join(proj_folder,proj_name+'.gpr')
        if not isfile(expected_ghidra_file):
            print("[!] Error: file {} not found".format(expected_ghidra_file))
            print(ghidra_output)
            return False

        return True

    except Exception as e:
        print("[!] Exception in ghidra_analyze\n{}".format(e))

def directory_walk(input_folder, output_folder):
    """Walk the directory tree and launch Ghidra."""
    try:
        print("[D] input_folder: {}".format(input_folder))
        print("[D] output_folder: {}".format(output_folder))

        export_error, export_success = 0, 0
        if not input_folder or not output_folder:
            print("[!] Error: missing input/output folder")
            return

        if not isdir(output_folder):
            mkdir(output_folder)

        for root, _, files in walk(input_folder):
            for fname in files:

                tmp_out = output_folder
                if not samefile(root, input_folder):
                    tmp_out = join(
                        output_folder,
                        relpath(root, input_folder))
                    if not isdir(tmp_out):
                        makedirs(tmp_out)

                input_path = join(root, fname)
                output_path = join(tmp_out, fname + ".i64")
                if export_idb(input_path, output_path):
                    export_success += 1
                else:
                    export_error += 1

        print("# Ghidra projs correctly exported: {}".format(export_success))
        print("# Ghidra projs error: {}".format(export_error))

    except Exception as e:
        print("[!] Exception in directory_walk\n{}".format(e))

def dir_walk_arm(input_folder, output_folder):
    """Walk directory and launch Ghidra on arm binaries"""
    try:
        print("[D] input_folder: {}".format(input_folder))
        print("[D] output_folder: {}".format(output_folder))

        export_error, export_success, export_skipped = 0, 0, 0
        if not input_folder or not output_folder:
            print("[!] Error: missing input/output folder")
            return

        if not isdir(output_folder):
            mkdir(output_folder)
        
        for root, _, files in walk(input_folder):
            for fname in [fname for fname in files if 'arm' in fname]:
                current_project_folder = join(output_folder, root.split('/')[-1])
                if not isdir(current_project_folder):
                    mkdir(current_project_folder)
                ghidra_project_name = fname
                bin_path = join(root, fname)
                if isfile(join(current_project_folder, ghidra_project_name)+'.gpr'):
                    print("[D] {} already exists".format(join(current_project_folder, ghidra_project_name)))
                    export_skipped += 1
                    continue
                if ghidra_analyze(current_project_folder, ghidra_project_name, bin_path):
                    export_success += 1
                else:
                    export_error += 1

        print("# Ghidra projs correctly exported: {}".format(export_success))
        print("# Ghidra projs error: {}".format(export_error))
        print("# Ghidra projs skipped (already exist): {}".format(export_skipped))

    except Exception as e:
        print("[!] Exception in directory_walk\n{}".format(e))

def dir_walk_px4(input_folder, output_folder):
    """Walk directory and launch Ghidra on arm binaries"""
    try:
        print("[D] input_folder: {}".format(input_folder))
        print("[D] output_folder: {}".format(output_folder))

        export_error, export_success, export_skipped = 0, 0, 0
        if not input_folder or not output_folder:
            print("[!] Error: missing input/output folder")
            return

        if not isdir(output_folder):
            mkdir(output_folder)
        
        for root, _, files in walk(input_folder):
            for fname in files:
                current_project_folder = join(output_folder, root.split('/')[-1])
                if not isdir(current_project_folder):
                    mkdir(current_project_folder)
                ghidra_project_name = fname
                bin_path = join(root, fname)
                if isfile(join(current_project_folder, ghidra_project_name)+'.gpr'):
                    print("[D] {} already exists".format(join(current_project_folder, ghidra_project_name)))
                    export_skipped += 1
                    continue
                if ghidra_analyze(current_project_folder, ghidra_project_name, bin_path):
                    export_success += 1
                else:
                    export_error += 1

        print("# Ghidra projs correctly exported: {}".format(export_success))
        print("# Ghidra projs error: {}".format(export_error))
        print("# Ghidra projs skipped (already exist): {}".format(export_skipped))

    except Exception as e:
        print("[!] Exception in directory_walk\n{}".format(e))

@click.command()
@click.option('--db1', is_flag=True)
@click.option('--db2', is_flag=True)
@click.option('--db1arm', is_flag=True)
@click.option('--dbpx4', is_flag=True)
@click.option('--dbvuln', is_flag=True)
@click.option('--dbdrone', is_flag=True)
@click.option('--test', is_flag=True)
def main(db1, db2, db1arm, dbpx4, dbvuln, dbdrone, test):
    """Launch Ghidra and analyze binaries."""
    if not isfile(GHIDRA_PATH):
        print("[!] Error: GHIDRA_PATH:{} not valid".format(GHIDRA_PATH))
        print("Use 'export GHIDRA_PATH=/full/path/to/ghidra-analyzeHeadless'")
        return

    no_action = True

    if db1:
        no_action = False
        directory_walk(
            join(BIN_FOLDER, 'Dataset-1'),
            join(GHIDRA_PROJ_FOLDER, 'Dataset-1'))
    if db2:
        no_action = False
        directory_walk(
            join(BIN_FOLDER, 'Dataset-2'),
            join(GHIDRA_PROJ_FOLDER, 'Dataset-2'))
    if db1arm:
        no_action = False
        dir_walk_arm(
            join(BIN_FOLDER, 'Dataset-1'),
            join(GHIDRA_PROJ_FOLDER, 'Dataset-1-arm'))
    if dbdrone:
        no_action = False
        dir_walk_px4(
            join(BIN_FOLDER, 'Dataset-drone-autopilot'),
            join(GHIDRA_PROJ_FOLDER, 'Dataset-drone-autopilot'))
    if dbpx4:
        no_action = False
        dir_walk_px4(
            join(BIN_FOLDER, 'Dataset-px4'),
            join(GHIDRA_PROJ_FOLDER, 'Dataset-px4'))
    if dbvuln:
        no_action = False
        directory_walk(
            join(BIN_FOLDER, 'Dataset-Vulnerability'),
            join(GHIDRA_PROJ_FOLDER, 'Dataset-Vulnerability'))
    if test:
        no_action = False
        proj_folder = join(GHIDRA_PROJ_FOLDER, "Dataset-1-test")
        if not isdir(proj_folder):
            mkdir(proj_folder)
        
        for current_bin_folder, ghidra_proj_name in TEST_BINARIES.items():
            current_project_folder = join(proj_folder, current_bin_folder.split('/')[0])
            if not isdir(current_project_folder):
                mkdir(current_project_folder)
            bin_path = join(BIN_FOLDER, "Dataset-1", current_bin_folder)
            if isfile(join(current_project_folder, ghidra_proj_name)+'.gpr'):
                print("[D] {} already exists".format(join(current_project_folder, ghidra_proj_name)))
                continue
            ghidra_analyze(current_project_folder, ghidra_proj_name, bin_path)
        
    if no_action:
        print("Please, select a Dataset to process. --help for options")
    else:
        print("That's all")
    return


if __name__ == "__main__":
    main()
