#!/usr/bin/env python3
"""Translate the base image's lld symbol ordering file to the v4 build (#745).

usage: port-symbol-order-v4.py [--images DIR] [--search N] <base order.txt> <v4 order.txt>

The base file (tools/make-symbol-order.py) lists `__imp__sub_X` for every
function a probe route entered, the most-called first. Each address is mapped
through tools/map-fh1-v4-addresses.py's function pairs, the ones it builds
up front: identical normalized bodies (`exact`) and call-graph pairs
(`anchored`). Only whole functions are reordered, so the per-address searches
are not needed. Within the first --search ranks (the hottest functions), an
unpaired address, often a small helper outside .pdata, goes through the
mapper's full search (about 0.1 s each); the rest are dropped and counted,
never guessed.
Functions new in v4 are unlisted, so lld places them after the ordered ones. Images as for tools/port-fh1-v4-analysis.py.
"""
import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "__imp__sub_"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--images", type=Path, default=ROOT / ".local/game/v4-images")
    parser.add_argument("--search", type=int, default=5000)
    parser.add_argument("base_order", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    v4map = load("v4map", ROOT / "tools/map-fh1-v4-addresses.py")
    port = load("v4port", ROOT / "tools/port-fh1-v4-analysis.py")
    base = (args.images / "default.base.bin").read_bytes()
    v4 = (args.images / "default.v4.bin").read_bytes()
    address_load = port.image_load(base)
    mapper = v4map.Mapper(v4map.Image(base, address_load), v4map.Image(v4, address_load))
    pairs = {**{a: (b, "exact") for a, b in mapper.exact.items()},
             **{a: (b, "anchored") for a, b in mapper.anchored.items()}}
    lines, seen, methods, dropped = [], set(), {}, 0
    for rank, line in enumerate(args.base_order.read_text(encoding="utf-8").split()):
        if not line.startswith(PREFIX):
            raise SystemExit(f"unexpected symbol {line!r}")
        address = int(line[len(PREFIX):], 16)
        mapped, method = pairs.get(address, (None, None))
        if mapped is None and rank < args.search:
            mapped, method = mapper.map(address, "function")
        if mapped is None or mapped in seen:
            dropped += 1
            continue
        seen.add(mapped)
        methods[method] = methods.get(method, 0) + 1
        lines.append(f"{PREFIX}{mapped:08X}")
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(lines)} functions ordered, {dropped} dropped; methods {methods}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
