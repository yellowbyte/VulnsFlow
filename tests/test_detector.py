from .. import detector

import os


def test_simple(tmpdir):
    folder = tmpdir
    filepath = os.path.join(os.getcwd(), "tests/programs/need_alias.out")
    detector.main(filepath, folder)
    output_file = os.path.join(folder, "need_alias.out.mono")
    with open(output_file, "r") as f:
        out = f.readlines()
        for o in out:
            assert o == "double_free,_main,12,0x100003f6c\n"