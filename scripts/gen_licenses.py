#!/usr/bin/env python3
"""Erzeugt THIRD_PARTY_LICENSES.md (Übersicht) und THIRD_PARTY_LICENSES.txt (Volltexte)
aus `cargo metadata`. Aufruf im Projektordner: python3 scripts/gen_licenses.py"""

import json
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LICENSE_RE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT)", re.I)

meta = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--format-version", "1", "--locked"], cwd=ROOT))
# Nur Crates, die wirklich ins Programm gelangen (alle Zielplattformen, ohne Test-Abhängigkeiten).
# `cargo tree` berücksichtigt – anders als `cargo metadata` – den Feature-Resolver korrekt.
tree = subprocess.check_output(
    ["cargo", "tree", "--target", "all", "-e", "normal,build", "--prefix", "none", "-f", "{p}"],
    cwd=ROOT, text=True)
used = {tuple(line.split()[:2]) for line in tree.splitlines() if line.strip()}
ids = {p["id"] for p in meta["packages"] if (p["name"], "v" + p["version"]) in used}
direct = {d["name"] for p in meta["packages"] if p["name"] == "doclatch"
          for d in p["dependencies"] if d["kind"] != "dev"}
pkgs = sorted((p for p in meta["packages"] if p["id"] in ids and p["name"] != "doclatch"),
              key=lambda p: (p["name"].lower(), p["version"]))


def license_files(p):
    d = Path(p["manifest_path"]).parent
    files = sorted(f for f in d.iterdir() if f.is_file() and LICENSE_RE.match(f.name))
    # Lizenzen eingebetteter Schriftarten (z. B. epaint_default_fonts/fonts/*.txt)
    if (d / "fonts").is_dir():
        files += sorted((d / "fonts").glob("*.txt"))
    if p.get("license_file"):
        lf = d / p["license_file"]
        if lf.is_file() and lf not in files:
            files.append(lf)
    return files


# Standardtexte für Crates ohne eigene Lizenzdatei – aus anderen Crates im Cargo-Cache.
REG = Path(next(p for p in meta["packages"] if p["name"] == "lopdf")["manifest_path"]).parent.parent
STANDARD = {
    "MIT": None,  # generischer Text, siehe unten
    "Apache-2.0": REG / "adler2-2.0.1" / "LICENSE-APACHE",
    "BSD-3-Clause": REG / "alloc-no-stdlib-2.0.4" / "LICENSE",  # gleicher Autor wie alloc-stdlib
    "BSL-1.0": REG / "error-code-3.4.0" / "LICENSE",            # gleicher Autor wie clipboard-win
}
MIT_TEXT = """MIT License

Copyright (c) <siehe Angabe beim jeweiligen Crate>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""


def pick_standard(expr):
    """Bei OR-Lizenzen MIT wählen, sonst die einzige Lizenz."""
    expr = expr or ""
    if "MIT" in expr:
        return "MIT"
    for k in ("Apache-2.0", "BSD-3-Clause", "BSL-1.0"):
        if k in expr:
            return k
    raise SystemExit(f"Kein Standardtext für {expr!r} hinterlegt")


counts = Counter(p["license"] or "?" for p in pkgs)
missing = []

md = ["# Lizenzen von Drittanbieter-Bibliotheken", "",
      f"Doclatch verwendet {len(pkgs)} Rust-Bibliotheken (Crates), davon {len(direct)} direkt "
      f"({', '.join(sorted(direct))}). Die Liste umfasst alle Zielplattformen (Linux, Windows, macOS).", "",
      "Die vollständigen Lizenztexte stehen in `THIRD_PARTY_LICENSES.txt`.", "",
      "## Zusammenfassung", "", "| Anzahl | Lizenz (SPDX) |", "|---:|---|"]
md += [f"| {n} | `{lic}` |" for lic, n in counts.most_common()]
md += ["", "## Alle Crates", "", "| Crate | Version | Lizenz | Quelle |", "|---|---|---|---|"]

txt = ["DRITTANBIETER-LIZENZEN – Doclatch", "=" * 72, ""]
for p in pkgs:
    name = f"**{p['name']}**" if p["name"] in direct else p["name"]
    repo = p.get("repository") or ""
    md.append(f"| {name} | {p['version']} | `{p['license'] or '?'}` | {repo} |")
    files = license_files(p)
    if not files:
        missing.append(p)
    txt += ["", "#" * 72, f"# {p['name']} {p['version']}", f"# Lizenz: {p['license'] or '?'}",
            f"# Quelle: {repo or '-'}", "#" * 72]
    for f in files:
        txt += ["", f"--- {f.name} ---", "", f.read_text(errors="replace").rstrip()]
    if not files:
        authors = ", ".join(p.get("authors") or []) or "die Autoren laut Quelle"
        txt += ["", f"(Kein Lizenztext im Paket enthalten. Lizenz laut Cargo.toml: {p['license']}.",
                f" Copyright (c) {authors}.",
                f" Es gilt der Standardtext im Anhang: {pick_standard(p['license'])}.)"]

txt += ["", "", "=" * 72, "ANHANG: STANDARD-LIZENZTEXTE (für Crates ohne eigene Lizenzdatei)", "=" * 72]
for name in sorted({pick_standard(p["license"]) for p in missing}):
    body = MIT_TEXT if STANDARD[name] is None else STANDARD[name].read_text()
    txt += ["", "-" * 72, f"{name}", "-" * 72, "", body.rstrip()]

(ROOT / "THIRD_PARTY_LICENSES.md").write_text("\n".join(md) + "\n")
(ROOT / "THIRD_PARTY_LICENSES.txt").write_text("\n".join(txt) + "\n")
print(f"{len(pkgs)} Crates, {len(missing)} ohne Lizenzdatei:")
for p in missing:
    print(f"  {p['name']} {p['version']} ({p['license']})")
