"""Download (or verify, or stage for upload) the data behind the paper's figures and tables.

The eval logs (``.eval``) and Inspect Scout scans the analysis reads are hosted in a
Hugging Face dataset repo at the same repo-relative paths the code uses, so a download
drops every file exactly where the scripts expect it. Each file's md5 and size are listed
in ``experiments/data/release_data_manifest.json``, together with the figures and tables
that read it.

Usage:
    uv run python experiments/scripts/release_data.py list
    uv run python experiments/scripts/release_data.py download --figure 3 6 --table 2
    uv run python experiments/scripts/release_data.py download --all
    uv run python experiments/scripts/release_data.py verify [--figure ... | --all]

    # maintainers, in the research repository (where the files sit in a DVC cache):
    # hardlink them into an upload folder, then upload it with the Hugging Face CLI
    uv run python experiments/scripts/release_data.py stage <outdir>
    hf upload-large-folder <repo-id> <outdir> --repo-type dataset

Every download includes the "base" group: the logs that define the 566-task BA1.0 split
(``BA10_UNION``), which almost every figure filters on.

Note: the transcripts contain fake credentials (API keys, SSH keys, passwords) that the
BashArena environment plants in every sandbox as side-task bait. They are not real.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "experiments" / "data" / "release_data_manifest.json"
DATASET_CARD = REPO_ROOT / "experiments" / "data" / "hf_dataset_card.md"
DVC_CACHE = REPO_ROOT / ".dvc" / "cache" / "files" / "md5"

HF_REPO_ID = "xtremekiwi/dtd-basharena-data"
HF_REVISION = "paper-v1"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def select(manifest: dict, args) -> list[str]:
    """Repo-relative paths for the requested groups (always including 'base')."""
    groups = manifest["groups"]
    if args.all:
        wanted = set(groups)
    else:
        wanted = {"base"}
        wanted |= {f"fig{n}" for n in args.figure or []}
        wanted |= {f"tab{n}" for n in args.table or []}
        wanted |= set(args.group or [])
        if wanted == {"base"}:
            sys.exit("Choose what to download: --figure N, --table N, --group NAME or --all "
                     "(see `release_data.py list`).")
    unknown = sorted(wanted - set(groups))
    if unknown:
        sys.exit(f"Unknown group(s) {unknown}; see `release_data.py list`.")
    return sorted(p for p, f in manifest["files"].items() if wanted & set(f["used_by"]))


def md5sum(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 24), b""):
            h.update(block)
    return h.hexdigest()


def local_ok(path: str, entry: dict, check_md5: bool) -> bool:
    p = REPO_ROOT / path
    if not p.is_file() or p.stat().st_size != entry["size"]:
        return False
    return not check_md5 or md5sum(p) == entry["md5"]


def cmd_list(manifest: dict, args) -> None:
    for name, g in manifest["groups"].items():
        if g["n_files"]:
            print(f"{name:17s} {g['n_files']:4d} files {g['bytes'] / 1e9:7.2f} GB  {g['title']}")
    total = sum(f["size"] for f in manifest["files"].values())
    print(f"{'all':17s} {len(manifest['files']):4d} files {total / 1e9:7.2f} GB")


def cmd_download(manifest: dict, args) -> None:
    from huggingface_hub import hf_hub_download

    paths = select(manifest, args)
    todo = [p for p in paths if not local_ok(p, manifest["files"][p], check_md5=False)]
    size = sum(manifest["files"][p]["size"] for p in todo)
    print(f"{len(paths)} files selected; {len(paths) - len(todo)} already present; "
          f"downloading {len(todo)} ({size / 1e9:.2f} GB) from {args.repo}@{args.revision}")
    if args.dry_run:
        for p in todo:
            print(f"  {p}")
        return
    def fetch(p: str) -> str | None:
        """Download one file with backoff on errors (network, 429); return an error or None."""
        for attempt in range(4):
            try:
                hf_hub_download(args.repo, p, repo_type="dataset", revision=args.revision,
                                local_dir=REPO_ROOT)
                return None
            except Exception as e:
                if attempt == 3:
                    return str(e)
                time.sleep(10 * 2 ** attempt)

    failed = []
    for i, p in enumerate(todo, 1):
        entry = manifest["files"][p]
        print(f"[{i}/{len(todo)}] {p} ({entry['size'] / 1e6:.0f} MB)", flush=True)
        err = fetch(p) or (None if local_ok(p, entry, check_md5=True) else "md5 mismatch")
        if err:
            print(f"  FAILED: {err}")
            failed.append(p)
    if failed:
        sys.exit(f"{len(failed)} file(s) failed; rerun the same command to retry them.")
    print("Done.")


def cmd_verify(manifest: dict, args) -> None:
    paths = select(manifest, args) if (args.all or args.figure or args.table or args.group) \
        else sorted(manifest["files"])
    bad = [p for p in paths if not local_ok(p, manifest["files"][p], check_md5=True)]
    for p in bad:
        print(f"MISSING OR CORRUPT: {p}")
    print(f"{len(paths) - len(bad)}/{len(paths)} files OK")
    if bad:
        sys.exit(1)


def cmd_stage(manifest: dict, args) -> None:
    if "TODO(" in DATASET_CARD.read_text():
        sys.exit(f"{DATASET_CARD.relative_to(REPO_ROOT)} still has TODO( placeholders; fill them in first.")
    out = Path(args.outdir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for p, entry in manifest["files"].items():
        src = DVC_CACHE / entry["md5"][:2] / entry["md5"][2:]
        if not src.is_file():
            sys.exit(f"{p}: not in the local DVC cache ({src}); run `dvc fetch` first.")
        dst = out / p
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            dst.unlink()
        try:
            os.link(src, dst)
        except OSError:  # different filesystem
            shutil.copy2(src, dst)
    shutil.copy2(DATASET_CARD, out / "README.md")
    shutil.copy2(MANIFEST, out / MANIFEST.name)
    total = sum(f["size"] for f in manifest["files"].values())
    print(f"Staged {len(manifest['files'])} files ({total / 1e9:.1f} GB) + README.md + "
          f"{MANIFEST.name} in {out}\nUpload with:\n"
          f"  hf upload-large-folder {HF_REPO_ID} {out} --repo-type dataset")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show the downloadable groups and their sizes")
    for name in ("download", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--figure", type=int, nargs="+", metavar="N", help="paper figure number(s)")
        p.add_argument("--table", type=int, nargs="+", metavar="N", help="paper table number(s)")
        p.add_argument("--group", nargs="+", help="other groups by name (see `list`)")
        p.add_argument("--all", action="store_true", help="every file (about 89 GB)")
        if name == "download":
            p.add_argument("--repo", default=HF_REPO_ID)
            p.add_argument("--revision", default=HF_REVISION)
            p.add_argument("--dry-run", action="store_true", help="list the files without downloading")
    p = sub.add_parser("stage", help="maintainers: build the upload folder from the local DVC cache")
    p.add_argument("outdir")
    args = ap.parse_args()
    manifest = load_manifest()
    {"list": cmd_list, "download": cmd_download, "verify": cmd_verify, "stage": cmd_stage}[args.cmd](manifest, args)


if __name__ == "__main__":
    main()
