from copy import deepcopy
from core import FlowAnalysis, MayAlias

import binaryninja
import sys
import os


class VulnsDetector(FlowAnalysis):

    def __init__(self, method, deallocation_methods=None):
        self.method = method
        self.deallocation_methods = deallocation_methods
        self.alias = MayAlias(method)
        self.reporter = list()
        super().__init__(method.hlil, "forward")

    def flow_through(self, bb, IN):
        """Fact-affecting flow functions for UAF and DF detections"""
        IN_wip = deepcopy(IN)
        for instr in bb:
            self.unitToBeforeFlow[instr.instr_index] = IN_wip
            if (
                    instr.operation.name == "HLIL_CALL" and
                    instr.dest.value.type.name == "ConstantPointerValue"
            ):
                # callee is explicit
                callee_addr = instr.dest.value.value
                assert "free" in self.deallocation_methods.keys()
                if callee_addr == self.deallocation_methods["free"]:
                    if (
                            len(instr.params) != 1 or
                            instr.params[0].operation.name != "HLIL_VAR"
                    ):
                        continue
                    # callee is free()
                    free_var = instr.params[0].var
                    if free_var.name in IN_wip.keys():
                        self.update_reporter(instr, free_var, IN_wip, "double_free")
                    elif len(IN_wip) != 0:
                        # alias query of free_var with each dataflow fact in IN_wip
                        for in_var in IN_wip.keys():
                            if self.alias.is_alias(free_var.name, in_var,
                                                   instr.instr_index):
                                self.update_reporter(instr, free_var, IN_wip,
                                                     "double_free", True)

                    # create a new copy so previously assigned
                    # unitTo{Before,After}Flow are not affected
                    IN_wip = deepcopy(IN_wip)
                    self.update_IN(instr, free_var, IN_wip)
                else:
                    # other calls
                    for param in instr.params:
                        if param.operation.name != "HLIL_VAR":
                            continue
                        if param.var.name in IN_wip.keys():
                            self.update_reporter(instr, param.var, IN_wip,
                                                 "use-after-free")
                        elif len(IN_wip) != 0:
                            # alias query of free_var with each dataflow fact in IN_wip
                            for in_var in IN_wip.keys():
                                if self.alias.is_alias(param.var.name, in_var,
                                                       instr.instr_index):
                                    self.update_reporter(instr, param.var, IN_wip,
                                                         "double_free", True)

            elif instr.operation.name == "HLIL_ASSIGN":
                instr_src = instr.src
                instr_dest = instr.dest
                if instr_src.operation.name == "HLIL_DEREF":
                    for var in instr_src.vars:
                        if var.name in IN_wip.keys():
                            self.update_reporter(instr, var, IN_wip, "use-after-free")
                        elif len(IN_wip) != 0:
                            # alias query of free_var with each dataflow fact in IN_wip
                            for in_var in IN_wip.keys():
                                if self.alias.is_alias(var.name, in_var,
                                                       instr.instr_index):
                                    self.update_reporter(instr, var, IN_wip,
                                                         "double_free", True)

                if instr_dest.operation.name == "HLIL_VAR":
                    instr_dest_var = instr_dest.var
                    if instr_dest_var in IN_wip.keys():
                        # KILL the var
                        del IN_wip[instr_dest_var]
            self.unitToAfterFlow[instr.instr_index] = IN_wip

        OUT = IN_wip
        return OUT

    @staticmethod
    def update_IN(instr, var, IN):
        """Update dataflow facts"""
        if var.name in IN.keys():
            IN[var.name].append(instr.instr_index)
        else:
            IN[var.name] = [instr.instr_index]

    @staticmethod
    def new_initial_flow():
        """Initial dataflow container which is a dict"""
        return dict()

    @staticmethod
    def merge(in1, in2):
        """Combine two sets since the abstract domain is the powerset lattice"""
        out1 = deepcopy(in1)
        out2 = deepcopy(in2)
        # MAY analysis
        return out1 | out2

    def update_reporter(self, instr, var, IN, vuln_type, isAlias=False):
        """Track the detected UAF or DF"""
        if isAlias:
            self.reporter.append(
                (vuln_type + "," + self.method.name + "," +
                 str(instr.instr_index) + "," + hex(instr.address) + "\n")
            )
        elif (
                var.name in IN.keys() and
                (instr.instr_index not in IN[var.name] or len(IN[var.name]) != 1)
        ):
            # the free param at instr not seen before
            # or there are multiple instrs with the same param
            # if it's latter, we have to over-approximate
            self.reporter.append(
                (vuln_type + "," + self.method.name + "," +
                 str(instr.instr_index) + "," + hex(instr.address) + "\n")
            )


if __name__ == "__main__":
    # identify free from symbol table
    # if not in symbol table, the binary does not call free anywhere
    filepath = sys.argv[1]
    filename = os.path.basename(filepath)
    print("apk: " + filename)
    output_file = open("target/" + filename + ".mono", "w")
    bv = binaryninja.load(filepath)
    free_sym = "free"
    if free_sym not in bv.symbols:
        free_sym = "_free"
        if free_sym not in bv.symbols:
            exit(0)
    # identify the imported function address for free
    free = bv.symbols[free_sym]
    addr_found = False
    free_addr = None
    for sym in free:
        if sym.type.name == "ImportedFunctionSymbol":
            addr_found = True
            free_addr = sym.address
            break
    if not addr_found:
        # free address not found
        exit(0)
    # TODO: add C++ delete to `dangling_creators`
    dangling_creators = dict()
    dangling_creators["free"] = free_addr

    for func in bv.functions:
        #        if func.name != "_main":
        #            continue
        print("    func:" + func.name)
        vulns = VulnsDetector(func, dangling_creators)
        # output vulns identified
        if len(vulns.reporter) != 0:
            #            breakpoint()
            for vuln in vulns.reporter:
                output_file.write(vuln)
                output_file.flush()

    output_file.close()
