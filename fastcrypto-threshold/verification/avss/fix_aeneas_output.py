#!/usr/bin/env python3
# THIS FILE IS AI-ONLY
"""Work around two Aeneas output bugs in a generated Lean directory (Types.lean, Funs.lean):
* serde's trait structures are mutually recursive, which Lean rejects. Nothing we prove uses
  serialization, so each `serde_core.*` structure becomes an empty structure with the same name
  and parameters.
* `core.num.nonzero.ZeroablePrimitive` gets two fields named `markerCopyInst`. The second is
  renamed `markerCopyInst1`, also in the record literals that build instances of it."""
import re, sys, pathlib
d = pathlib.Path(sys.argv[1])
t = (d / "Types.lean").read_text()
chunks = t.split("\n\n")
out = []
for c in chunks:
    m = re.search(r"^structure (serde_core\.[\w.]+)(.*?)\bwhere\b", c, re.S | re.M)
    if m:
        doc = c[: c.find("@[")] if "@[" in c else c[: m.start()]
        c = doc + "structure " + m.group(1) + m.group(2) + "where"
    if re.search(r"^structure core\.num\.nonzero\.ZeroablePrimitive\b", c, re.M):
        c = c.replace('(parentClauses := ["markerCopyInst", "markerCopyInst"])',
                      '(parentClauses := ["markerCopyInst", "markerCopyInst1"])')
        i = c.rfind("  markerCopyInst :")
        c = c[:i] + "  markerCopyInst1 :" + c[i + len("  markerCopyInst :"):]
    out.append(c)
(d / "Types.lean").write_text("\n\n".join(out))
for f in d.glob("*.lean"):
    s = f.read_text()
    def fix(m):
        body = m.group(0)
        i = body.rfind("  markerCopyInst :=")
        return body[:i] + "  markerCopyInst1 :=" + body[i + len("  markerCopyInst :="):]
    s2 = re.sub(r"core\.num\.nonzero\.ZeroablePrimitive [^\n]*\n[^{]*:= \{\n  markerCopyInst :=[^\n]*\n  markerCopyInst :=[^\n]*\n\}", fix, s)
    if s2 != s:
        f.write_text(s2)
# The serde structures are empty now. Instances of them become empty records, and other
# definitions that use serde (the derived `serialize`/`deserialize` code) become axioms.
for f in d.glob("Funs*.lean"):
    cs = f.read_text().split("\n\n")
    for k, c in enumerate(cs):
        m = re.search(r"^(def|impl_def|noncomputable def)\s", c, re.M)
        if not m:
            continue
        j = c.find(":= {", m.start())
        if j >= 0 and c.rstrip().endswith("}"):
            # An instance: empty it only if it is an instance of a serde trait.
            if re.search(r":\s*serde_core\.[\w.]+\b[^\n]*(\n[^\n]*)*?\s*:= \{", c[m.start(): j + 4]) and \
               not re.search(r":\s*fastcrypto\.", c[m.start(): j]):
                cs[k] = c[:j] + ":= {}"
            continue
        if "serde_core." not in c:
            continue
        e = re.search(r"\n?\s*:=( do)?\s*\n", c[m.start():])
        if e:
            sig = c[: m.start() + e.start()]
            head, decl = sig[: m.start()], sig[m.end():].lstrip()
            head = re.sub(r"@\[[^\]]*\]\s*\n", "", head)
            cs[k] = head + "axiom " + decl
    f.write_text("\n\n".join(cs))
# An instance whose fields refer back to the instance itself (a trait's default method used in its
# own impl) cannot be defined in Lean; it becomes an axiom.
for f in d.glob("Funs*.lean"):
    cs = f.read_text().split("\n\n")
    for k, c in enumerate(cs):
        m = re.search(r"^impl_def\s+([\w.]+)", c, re.M)
        if not m:
            continue
        j = c.find(":= {", m.end())
        if j >= 0 and m.group(1) in c[j:]:
            head = re.sub(r"@\[[^\]]*\]\s*\n", "", c[: m.start()])
            cs[k] = head + "axiom " + c[m.start() + len("impl_def"): j].strip()
    f.write_text("\n\n".join(cs))
# A function Aeneas could not translate has `sorry` as its body; it becomes an axiom instead.
for f in d.glob("Funs*.lean"):
    cs = f.read_text().split("\n\n")
    for k, c in enumerate(cs):
        m = re.search(r"^def\s", c, re.M)
        e = re.search(r"\n\s*:= do\n\s*sorry\s*$", c)
        if m and e:
            head = re.sub(r"@\[[^\]]*\]\s*\n", "", c[: m.start()])
            cs[k] = head + "axiom " + c[m.end(): e.start()].lstrip()
    f.write_text("\n\n".join(cs))
# Models of standard-library functions that Aeneas' library does not have yet.
MODELS = {
    "core.result.Result.is_err": (
        "def core.result.Result.is_err\n  {T : Type _} {E : Type _} : core.result.Result T E → Result Bool\n"
        "  | .Ok _ => ok false\n  | .Err _ => ok true"),
    "SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter": (
        "def SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter\n"
        "  {T : Type _} (A : Type _) (v : alloc.vec.Vec T) : Result (core.slice.iter.Iter T) :=\n"
        "  ok ⟨alloc.vec.Vec.deref v, 0⟩"),
}
for f in d.glob("FunsExternal.lean"):
    s = f.read_text()
    for name, model in MODELS.items():
        s = re.sub(r"axiom " + re.escape(name) + r"\n(?:[^\n]+\n)*", model + "\n", s)
    f.write_text(s)
# A Rust parameter named `nodes` shadows the `nodes` module, so references to the module's
# functions are written from the root namespace.
f = d / "Funs.lean"
s = f.read_text()
s = re.sub(r"(?<![\w.])nodes\.Nodes\.", "_root_.nodes.Nodes.", s)
f.write_text(s)
print("fixed", d)
