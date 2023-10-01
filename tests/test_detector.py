from .. import detector

import os


def test_libhello_libs(tmpdir):
    folder = tmpdir
    filepath = os.path.join(os.getcwd(), "tests/programs/libhello_libs.so")
    detector.main(filepath, folder)
    output_file = os.path.join(folder, "libhello_libs.so.mono")
    expected = {
        "use-after-free,Java_com_example_hellolibs_NativeCall_echoJNI,9,0xc1c\n",
        "double-free,Java_com_example_hellolibs_NativeCall_echoJNI,13,0xc54\n",
    }
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        out = f.readlines()
        print(out)
        assert len(out) != 0
        assert set(out) == expected


def test_libhello_libs1(tmpdir):
    folder = tmpdir
    filepath = os.path.join(os.getcwd(), "tests/programs/libhello_libs1.so")
    detector.main(filepath, folder)
    output_file = os.path.join(folder, "libhello_libs1.so.mono")
    expected = {
        "double-free,Java_com_example_hellolibs_NativeCall_echoJNI,12,0xbf0\n",
        "use-after-free,Java_com_example_hellolibs_NativeCall_echoJNI,8,0xbbc\n",
    }
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        out = f.readlines()
        print(out)
        assert len(out) != 0
        assert set(out) == expected


def test_libhello_libs2(tmpdir):
    folder = tmpdir
    filepath = os.path.join(os.getcwd(), "tests/programs/libhello_libs2.so")
    detector.main(filepath, folder)
    output_file = os.path.join(folder, "libhello_libs2.so.mono")
    expected = {
        "double-free,Java_com_example_hellolibs_NativeCall_echoJNI,15,0xc04\n",
    }
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        out = f.readlines()
        print(out)
        assert len(out) != 0
        assert set(out) == expected


def test_need_alias(tmpdir):
    folder = tmpdir
    filepath = os.path.join(os.getcwd(), "tests/programs/need_alias.out")
    detector.main(filepath, folder)
    output_file = os.path.join(folder, "need_alias.out.mono")
    expected = {
        "double-free,_main,12,0x100003f6c\n",
    }
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        out = f.readlines()
        print(out)
        assert len(out) != 0
        assert set(out) == expected


def test_cpp1(tmpdir):
    folder = tmpdir
    filepath = os.path.join(os.getcwd(), "tests/programs/cpp1.out")
    detector.main(filepath, folder)
    output_file = os.path.join(folder, "cpp1.out.mono")
    expected = {
        "double-free,_main,82,0x100003088\n",
    }
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        out = f.readlines()
        print(out)
        assert len(out) != 0
        assert set(out) == expected
