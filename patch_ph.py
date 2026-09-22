import re, yaml, sys

FRAG = "tools_selftest.ps1frag"


def build_step(ind):
    ps = open(FRAG).read().rstrip("\n").split("\n")
    blk = [ind + "- name: Page heap self test (instrument must fault)",
           ind + "  shell: pwsh",
           ind + "  run: |"]
    blk += [ind + "    " + p for p in ps]
    return blk


for f in sys.argv[1:]:
    s = open(f).read()
    s = s.replace("GlobalFlag -Value 0x200", "GlobalFlag -Value 0x02000000")
    s = re.sub(r"timeout-minutes: \d+", "timeout-minutes: 330", s)
    lines = s.split("\n")
    idx = None
    ind = None
    for i, l in enumerate(lines):
        m = re.match(r"^(\s*)- name: Upload evidence", l)
        if m:
            idx = i
            ind = m.group(1)
    if idx is None:
        print("NO ANCHOR", f)
        sys.exit(1)
    lines[idx:idx] = build_step(ind)
    out = "\n".join(lines)
    open(f, "w").write(out)
    d = yaml.safe_load(out)
    j = list(d["jobs"])[0]
    names = [x.get("name") for x in d["jobs"][j]["steps"]]
    print("OK", f, "timeout=", d["jobs"][j].get("timeout-minutes"), "last steps=", names[-3:])
