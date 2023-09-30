from binaryninja import *
from pprint import pprint

import ctypes
import sys


class Callgraph:

    def __init__(self, view, rootfunction=None):
        self.view = view
        self.rootfunction = rootfunction
        self.leafs = set()
        self.roots = set()
        self.not_leafs = set()
        self.callee2caller = dict()  # dict containing callee -> set(callers)
        self.caller2callee = dict()  # dict containing caller -> set(callees)
        self.collect_calls()

    def collect_calls(self):

        for function in self.view.functions:
            if not self.is_user_defined(function):
                continue
            refs = [r for r in self.view.get_code_refs(function.start)]
            if len(refs) == 0:
                self.roots.add(function)
            for ref in refs:
                caller = ref.function
                self.callee2caller[function] = self.callee2caller.get(function, set())
                self.caller2callee[caller] = self.caller2callee.get(caller, set())
                if function not in self.not_leafs:
                    self.leafs.add(function)
                call_il = caller.get_low_level_il_at(ref.address)
                if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                    self.callee2caller[function].add(caller)
                    self.caller2callee[caller].add(function)
                    self.not_leafs.add(caller)
                    if caller in self.leafs:
                        self.leafs.remove(caller)

    def is_user_defined(self, function):
        func_name = function.name
        if func_name in self.view.symbols:
            # function name is in imported symbols
            symbols = self.view.symbols[func_name]
            for sym in symbols:
                if (
                        sym.type == SymbolType.DataSymbol or
                        sym.type == SymbolType.FunctionSymbol
                ):
                    if sym.address == function.start:
                        # still user-defined functions although in symbol table
                        return True
        # not in symbol table
        # user-defined
        return True


def rto_traversal(cg):
    topological_order = list()
    wip_funcs = set()
    for func in cg.roots:
        wip_funcs.add(func)
        while len(wip_funcs) != 0:
            curr_func = wip_funcs.pop()
            if curr_func not in topological_order:
                topological_order.append(curr_func)
                if curr_func in cg.caller2callee:
                    for callee in cg.caller2callee[curr_func]:
                        wip_funcs.add(callee)

    # reverse topological ordering list to get reverse topological ordering
    return topological_order[::-1]


if __name__ == "__main__":
    filepath = sys.argv[1]
    bv = binaryninja.load(filepath)
    cg = Callgraph(bv)
    rto = rto_traversal(cg)
    pprint([f.name for f in rto])
    breakpoint()