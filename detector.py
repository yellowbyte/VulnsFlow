#!/usr/bin/env python3
from copy import deepcopy
from collections import namedtuple

import core
import binaryninja
import click
import os


Summary = namedtuple("Summary", ["args_free", "args_use", "ret_free"])


class VulnsDetector(core.FlowAnalysis):

    func_summaries = dict()

    def __init__(self, method, deallocation_methods=None):
        self.method = method
        self.deallocation_methods = deallocation_methods
        self.alias = core.MayAlias(method)
        # self.alias = core.DefaultAlias()
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
                callee_name = str(instr.dest)
                if (
                        callee_addr in self.deallocation_methods.values() or
                        callee_name == "operator delete[]" or
                        callee_name == "operator delete"
                ):
                    # callee is heap deallocation: free, delete, delete[]
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
                    if (
                            instr_dest_var in IN_wip.keys() and
                            instr_src.operation.name != "HLIL_CALL"
                    ):
                        # TODO: fix this part when considering program summaries
                        # TODO: since the callee can either kill or keep the
                        # TODO: dangling pointer
                        # KILL the var
                        # lhs is a dataflow fact that is overwritten
                        del IN_wip[instr_dest_var]
            self.unitToAfterFlow[instr.instr_index] = IN_wip

        OUT = IN_wip
        return OUT

    @staticmethod
    def update_IN(instr, var, IN):
        """Update dataflow facts"""
        if var.name in IN.keys():
            IN[var.name].add(instr.instr_index)
        else:
            IN[var.name] = {instr.instr_index}

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


def get_danglers(bv):
    # identify free from symbol table
    # if not in symbol table, the binary does not call free anywhere
    dangling_creators = dict()
    free_sym = "free"
    if free_sym not in bv.symbols:
        free_sym = "_free"
        if free_sym not in bv.symbols:
            free_sym = None
    if free_sym:
        # identify the imported function address for free
        free = bv.symbols[free_sym]
        free_addr = None
        for sym in free:
            if sym.type.name == "ImportedFunctionSymbol":
                free_addr = sym.address
                break
        dangling_creators["free"] = free_addr
    return dangling_creators


def main(filepath, output_dir):
    filename = os.path.basename(filepath)
    print(f"apkpath: {filepath}, apkname: {filename}")
    output_filepath = os.path.join(output_dir, filename + ".mono")
    output_file = open(output_filepath, "w")
    bv = binaryninja.load(filepath)

    dangling_creators = get_danglers(bv)
    # create callgraph (OG)
    # NO: create on-demand callgraphs for functions not in callgraph (OG)
    # NO: - extend on-demand callgraph with callee if a dangling pointer flows into it
    # NO: - extend on-demand callgraph with callers if a dangling pointer is returned
    # NO: - combine overlapping on-demand callgraphs
    # NO: if on-demand callgraph overlaps with callgraph (OG), add to OG
    # NO: callgraph (OG) may have multiple entry points therefore
    # traverse callgraph in RTO
    # TODO: create function summaries
    # create unit tests and CI/CD
    vuln_lines = set()
    cg = core.Callgraph(bv)
    rto = core.rto_traversal(cg)
    for func in rto:
        #        if func.name != "_main":
        #            continue
        print(f"    func({hex(func.start)}): {func.name}")
        vulns = VulnsDetector(func, dangling_creators)
        # output vulns identified
        if len(vulns.reporter) != 0:
            # breakpoint()
            for vuln in vulns.reporter:
                vuln_lines.add(vuln)

    # write to file unique findings
    for vuln in vuln_lines:
        output_file.write(vuln)
        output_file.flush()
    output_file.close()


@click.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.argument('output_dir', default="target")
def cli(filepath, output_dir):
    main(filepath, output_dir)


if __name__ == "__main__":
    cli()