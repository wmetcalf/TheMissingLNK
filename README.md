# TheMissingLNK

Shell.Explorer.1 OLE parser with IDLIST decoding and JSON reporting.

## Usage

```bash
python3 damissinglnk.py <file|glob|dir>
python3 damissinglnk.py --knownfolders /path/to/knownfolders.json <file|glob|dir>
python3 damissinglnk.py <file|glob|dir> --json-out /path/to/output.json
```

By default, outputs a JSON report to `dumps/shell_explorer_idlists.json`.

## Requirements

```bash
pip install -r requirements.txt
```
