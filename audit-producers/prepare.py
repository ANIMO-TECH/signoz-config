#!/usr/bin/env python3
"""Fetch one exact public upstream commit and apply its reviewed patch to a new directory."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('platform', choices=['coolify', 'signoz'])
parser.add_argument('destination', type=Path)
args = parser.parse_args()
files = Path(__file__).resolve().parent / args.platform
pin = json.loads((files / 'upstream.json').read_text())
patch = files / 'operations.patch'
if hashlib.sha256(patch.read_bytes()).hexdigest() != pin['patch_sha256']:
    raise SystemExit('Patch digest mismatch')
if args.destination.exists():
    raise SystemExit('Destination exists; use a new empty path')
args.destination.mkdir(parents=True)

def git(*parts):
    return subprocess.check_output(['git', '-C', str(args.destination), *parts], text=True)

git('init', '-q')
git('remote', 'add', 'origin', 'https://github.com/' + pin['repository'] + '.git')
git('fetch', '--depth=1', 'origin', pin['commit'])
git('checkout', '--detach', 'FETCH_HEAD')
if git('rev-parse', 'HEAD').strip() != pin['commit']:
    raise SystemExit('Upstream commit mismatch')
git('apply', '--check', str(patch))
git('apply', str(patch))
print(f"Prepared {args.platform} {pin['version']} ({pin['commit']}) in {args.destination}")
