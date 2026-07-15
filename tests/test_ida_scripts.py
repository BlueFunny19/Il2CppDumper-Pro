import json
import runpy
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(str(__file__).replace("\\", "/")).resolve().parents[1]
CALLS = {"functions": [], "names": [], "comments": [], "headers": [], "types": []}


def stub(name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    sys.modules[name] = module
    return module


stub("ida_auto", auto_wait=lambda: None)
stub(
    "ida_bytes",
    set_cmt=lambda ea, text, repeatable: CALLS["comments"].append(
        (ea, text, repeatable)
    )
    or True,
)
stub(
    "ida_funcs",
    get_func=lambda ea: None,
    add_func=lambda start, end: CALLS["functions"].append((start, end)) or True,
)
ida_name = stub("ida_name", MAXNAMELEN=512, SN_NOWARN=1, SN_NOCHECK=2)
ida_name.set_name = lambda ea, name, flags: CALLS["names"].append(
    (ea, name, flags)
) or True
stub("ida_nalt", get_imagebase=lambda: 0x1000)
stub(
    "ida_segment",
    getseg=lambda ea: types.SimpleNamespace(end_ea=0x2000)
    if 0x1000 <= ea < 0x2000
    else None,
)
ida_typeinf = stub(
    "ida_typeinf",
    HTI_DCL=1,
    HTI_NWR=2,
    HTI_RELAXED=4,
    HTI_SEMICOLON=8,
    get_idati=lambda: object(),
)
ida_typeinf.parse_decls = lambda til, text, printer, flags: CALLS["headers"].append(
    (text, flags)
) or 0
ida_typeinf.apply_cdecl = lambda til, ea, decl: CALLS["types"].append(
    (ea, decl)
) or True


with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    json_path = directory / "script.json"
    header_path = directory / "il2cpp.h"
    json_path.write_text(
        json.dumps(
            {
                "Addresses": [0x10, 0x20],
                "ScriptMethod": [
                    {
                        "Address": 0x10,
                        "Name": "Type$$Method",
                        "Signature": "void Method()",
                    }
                ],
                "ScriptString": [{"Address": 0x30, "Value": "hello"}],
                "ScriptMetadata": [
                    {"Address": 0x40, "Name": "Type_c", "Signature": "void*"}
                ],
                "ScriptMetadataMethod": [
                    {"Address": 0x50, "Name": "MethodInfo", "MethodAddress": 0x10}
                ],
            }
        ),
        encoding="utf-8",
    )
    header_path.write_text("typedef void *Il2CppClass;", encoding="utf-8")
    paths = iter((str(json_path), str(json_path), str(header_path)))
    stub("ida_kernwin", ask_file=lambda *args: next(paths))

    runpy.run_path(str(ROOT / "Il2CppDumper" / "ida_py3.py"), run_name="__main__")
    runpy.run_path(
        str(ROOT / "Il2CppDumper" / "ida_with_struct_py3.py"),
        run_name="__main__",
    )


assert len(CALLS["functions"]) == 2, CALLS
assert len(CALLS["names"]) == 8, CALLS
assert len(CALLS["comments"]) == 8, CALLS
assert len(CALLS["headers"]) == 1, CALLS
assert len(CALLS["types"]) == 2, CALLS
assert all(declaration.endswith(";") for _, declaration in CALLS["types"]), CALLS
print("IDAPython compatibility smoke test passed")
