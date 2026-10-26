# Catalog1

The Catalog1 experiment computes MinHash signatures from the basic-block bytes
exported by the Ghidra ACFG disassembly script.

## Requirements
1. Compile the Catalog1 library:
```
(cd catalog1/; make)
```

After compilation, `libcatalog1.so` will appear under `catalog1/bin`.

2. Generate the Ghidra ACFG disassembly files by running the repository's
   `scripts/entrypoint.sh` script.

## Ghidra conversion

- **input**: a directory of `*_acfg_disasm.json` files.
- **output**: one CSV file per Catalog1 signature size (default: `[16, 32, 64, 128]`).

Example: generate Catalog1 results through the wrapper-compatible runner:
```bash
./runCatalog1.sh Dataset-Vulnerability
```

The runner reads testing ACFG files when split data is present, otherwise it
uses the combined ACFG directory. To invoke the converter directly:

```bash
python3 ghidra_catalog1.py \
  --input-dir ../../../DBs/Dataset-Vulnerability/features/acfg_disasm \
  --output-prefix Dataset-Vulnerability_catalog1
```


Run unit tests:
```bash
python3 -m unittest test_catalog1.py

# optional - test on multiple files
python3 -m unittest test_large_catalog1.py
```

### Expected output
The converter produces a set of CSV files with the following columns:
* `path`: Ghidra project path
* `address`: function address
* `size`: function size
* `catalog_hash_list`: catalog hashes, separated by `;`
* `time`: time to calculate the Catalog1 hashes on the function.

To compute the similarity between two Catalog1 signatures, use the Jaccard similarity as in the following example:
```python
def jaccard_similarity(s1, s2):
    return len(set(s1) & set(s2)) / len(set(s1) | set(s2))

a = [10534612, 42437122, 187632428, 38160894, 167893582, 20517613, 328764745, 40669729]
b = [15508139, 42437122, 83784247, 138119612, 167793573, 29886129, 35551260, 1210122]
print(jaccard_similarity(a, b)) # 0.06666666666666667
print(jaccard_similarity(a, a)) # 1.0
```

**Note:** if the function has less than 4 bytes, `min_function_size_error` is inserted in the `catalog_hash_list` column.

## More info about the Catalog1 library
Catalog1 implements the MinHash algorithm and the library can be used to compute a signature over any stream of binary data:
```python
from catalog1.catalog_fast import sign
from catalog1.catalog_slow import slow_sign

SIG_SIZE = 128 # Example values: 16, 32, 64, 128

binary_data = "..."

# C implementation (fast)
signature = sign(binary_data, SIG_SIZE)

# Python3 implementation
signature_slow = slow_sign(binary_data, SIG_SIZE)
```

## Copyright information about Catalog1
The code of [Catalog1](catalog1) is taken from the xorpd repository of the [fcatalog_server](https://github.com/xorpd/fcatalog_server), which is released under the GNU General Public License v3.0.

* [Link](https://www.xorpd.net/pages/fcatalog.html) to the blogpost.    
* [Link](https://github.com/xorpd/fcatalog_server/tree/master/catalog1) to the Catalog1 C implementation.
* [Link](https://github.com/xorpd/fcatalog_server/blob/master/fcatalog/fcatalog/catalog1.py) to the Catalog1 Python3 implementation.

Changelog wrt the [original version](https://github.com/xorpd/fcatalog_server/tree/master/catalog1):

* The `catalog1/Makefile` has been modified.
