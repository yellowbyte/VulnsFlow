from binaryninja import *

import ctypes
import sys


class Callgraph:

    def __init__(self, view, rootfunction=None):
        self.view = view
        self.rootfunction = rootfunction
        self.leafs = set()
        self.calls = {}  # dict containing callee -> set(callers)
        self.collect_calls()

    def collect_calls(self):

        for function in self.view.functions:
            for ref in self.view.get_code_refs(function.start):
                caller = ref.function
                self.calls[function] = self.calls.get(function, set())
                self.leafs.add(function)
                call_il = caller.get_low_level_il_at(ref.address)
                if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                    self.calls[function].add(caller)
                    self.leaf.remove(caller)


if __name__ == "__main__":
    filepath = sys.argv[1]
    bv = binaryninja.load(filepath)
    cg = Callgraph(bv)
    breakpoint()