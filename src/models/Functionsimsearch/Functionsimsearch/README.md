# FSS: Function Sim Search
The FSS experiment has two steps. [The first](#part-1) converts Ghidra ACFG
disassembly JSON into FunctionSimSearch input. [The second](#part-2) hashes
that input and produces four CSV files, one per feature-weight configuration.

This tool is based on this project by Thomas Dullien: https://github.com/googleprojectzero/functionsimsearch. We forked the repository (commit `ec5d9e1224ff915b3dc9e7af19e21e110c25239c`) and we customized it to our needs, integrated our layers of analysis, and tweaked the docker container. The specific changes to the initial Google P0 repository are documented in the file `functionsimsearch.patch`.


## Part 1

- **Input**: a directory of Ghidra `*_acfg_disasm.json` files.
- **Output**: one `*_fss.json` file per ACFG input file.

Generate all available split or combined FSS inputs for a dataset:
```bash
./runpart1.sh Dataset-Vulnerability
```

Or invoke the converter directly:

```bash
python3 ghidra_to_fss.py \
  --input-dir ../../../DBs/Dataset-Vulnerability/features/acfg_disasm \
  --output-dir IDA_fss/fss_Dataset-Vulnerability
```


## Part 2
- **Input**: a directory with JSONs produced by `ghidra_to_fss.py`
- **Output**: four CSVs, each of which containing the results for one of the specific four tested configurations

Example input: [testdata/fss_jsons](testdata/fss_jsons).
Example output: [testdata/fss_csvs](testdata/fss_csvs).

### Tested configurations:
The following are the four configurations we tested. In each test we assign different weights to each feature.

| config | immediate | mnemonic | graphlet |
|--------|-----------|----------|----------|
|      1 |      4.00 |     0.05 |     1.00 |
|      2 |      0.00 |     0.00 |     1.00 |
|      3 |      0.00 |     1.00 |     1.00 |
|      4 |      1.00 |     1.00 |     1.00 |


### Build and run the Docker container
These are the concrete steps to run the analysis within the provided Docker container:

- Clone the functionsimsearch repository and apply the patch:
```bash
git clone https://github.com/googleprojectzero/functionsimsearch;
( cd functionsimsearch ; git checkout ec5d9e1224ff915b3dc9e7af19e21e110c25239c ; patch -s -p0 < ../functionsimsearch.patch );
cp fss_simhasher.py ./functionsimsearch/;
```

- Build the docker image:
```bash
docker build -t fss ./functionsimsearch
```

- Run the main script within the docker container: 
```bash
docker run --rm -it fss -v <full-path-to-the-input-jsons-dir>:/input -v <full-path-to-the-output-csvs-dir>:/output /fss_simhasher.py
```

Example (it creates four CSVs in `/tmp/fss_csvs`):
```bash
docker run --rm -v $(pwd)/testdata/fss_jsons:/input -v /tmp/fss_csvs:/output -it fss /fss_simhasher.py
```

- Run the script for the Dataset-2
```bash
docker run --rm -v $(pwd)/../../../DBs/Dataset-2/features/fss_Dataset-2:/input -v $(pwd)/../../../Results/FunctionSimSearch/Dataset-2:/output -it fss /fss_simhasher.py

```

## Copyright information about FunctionSimSearch

[FunctionSimSearch](https://github.com/googleprojectzero/functionsimsearch) is released under Apache License 2.0.

[IDA_fss.py](IDA_fss/IDA_fss.py) includes part of the code from https://github.com/williballenthin/python-idb/ and https://github.com/googleprojectzero/functionsimsearch which are licensed under Apache License 2.0.

