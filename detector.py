#!/usr/bin/env python3
from copy import deepcopy
from collections import namedtuple
from typing import cast, Dict, Optional

import core
import binaryninja
import click
import os


Summary = namedtuple("Summary", ["args_use", "args_free", "ret_free"])


class VulnsDetector(core.FlowAnalysis):
    func_summaries: Dict[binaryninja.function.Function, Summary] = dict()

    def __init__(
            self, method, bv: binaryninja.binaryview.BinaryView,
            deallocation_methods=None
    ):
        self.method: binaryninja.function.Function = method
        self.bv: binaryninja.binaryview.BinaryView = bv
        self.deallocation_methods: Dict[str, int] = deallocation_methods
        self.alias = core.MayAlias(method)
        # self.alias = core.DefaultAlias()
        self.reporter: list = list()
        # list of binaryninja.variable.Variable
        self.args: list[binaryninja.variable.Variable] = self.method.parameter_vars.vars
        self.args_use_sum: list[bool] = [False] * len(self.args)   # F: none, T: use
        self.args_free_sum: list[bool] = [False] * len(self.args)  # F: none, T: free
        self.ret_free_sum: bool = False  # F: none, T: free
        super().__init__(method.hlil, "forward")
        VulnsDetector.func_summaries[method] = Summary(
            self.args_use_sum,
            self.args_free_sum,
            self.ret_free_sum
        )

    def flow_through(self, bb, IN):
        """Fact-affecting flow functions for UAF and DF detections"""
        IN_wip: Dict[str, set[int]] = deepcopy(IN)
        for instr in bb:
            self.unitToBeforeFlow[instr.instr_index] = IN_wip
            if (
                    instr.operation.name == "HLIL_CALL" and
                    # explicit callee
                    instr.dest.value.type.name == "ConstantPointerValue"
            ):
                instr = cast(binaryninja.highlevelil.HighLevelILCall, instr)
                IN_wip = self.handle_call(instr, IN_wip)
            elif instr.operation.name == "HLIL_ASSIGN":
                instr_src = instr.src
                instr_dest = instr.dest
                # handle instr_src
                if instr_src.operation.name == "HLIL_DEREF":
                    for var in instr_src.vars:
                        self.update_args_use_sum(var)
                        if var.name in IN_wip.keys():
                            self.update_reporter(instr, var, IN_wip, "use-after-free")
                        elif len(IN_wip) != 0:
                            # alias query of free_var with each dataflow fact in IN_wip
                            for in_var in IN_wip.keys():
                                if self.alias.is_alias(var.name, in_var,
                                                       instr.instr_index):
                                    self.update_reporter(instr, var, IN_wip,
                                                         "use-after-free", True)
                elif instr_src.operation.name == "HLIL_CALL":
                    # rhs is a call instruction
                    instr = cast(binaryninja.highlevelil.HighLevelILCall, instr)
                    if instr_dest.operation.name == "HLIL_VAR":
                        # add instr_dest to IN_wip if callee return free'd ptr
                        instr_dest_var = instr_dest.var
                        IN_wip = self.handle_call(instr_src, IN_wip, instr_dest_var)
                    else:
                        IN_wip = self.handle_call(instr_src, IN_wip)
                # handle instr_dest
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
            elif instr.operation.name == "HLIL_RET":
                # check return instruction for summary
                # update self.ret_free_sum if return value in IN_wip
                self.update_ret_free_sum(instr, IN_wip)
                if len(instr.src) == 1:
                    instr_src = instr.src[0]
                    if instr_src.operation.name == "HLIL_CALL":
                        if self.is_free(instr_src):
                            self.ret_free_sum = True
                        instr = cast(binaryninja.highlevelil.HighLevelILCall,
                                     instr)
                        IN_wip = self.handle_call(instr_src, IN_wip)

            self.unitToAfterFlow[instr.instr_index] = IN_wip

        OUT = IN_wip
        return OUT

    def handle_call(
            self, instr: binaryninja.highlevelil.HighLevelILCall,
            IN_wip: Dict[str, set[int]],
            dest_var: Optional[binaryninja.variable.Variable] = None
    ) -> Dict[str, set[int]]:
        if self.is_free(instr):
            # callee is free()
            instr_params: list[binaryninja.highlevelil.HighLevelILInstruction] = (
                instr.params
            )
            instr_param: binaryninja.highlevelil.HighLevelILVar = (
                cast(binaryninja.highlevelil.HighLevelILVar, instr_params[0])
            )
            free_var: binaryninja.variable.Variable = instr_param.var
            self.update_args_free_sum(free_var)
            if free_var.name in IN_wip.keys():
                self.update_reporter(instr, free_var, IN_wip, "double-free")
            elif len(IN_wip) != 0:
                # alias query of free_var with each dataflow fact in IN_wip
                for in_var in IN_wip.keys():
                    if self.alias.is_alias(free_var.name, in_var,
                                           instr.instr_index):
                        self.update_reporter(instr, free_var, IN_wip,
                                             "double-free", True)

            # create a new copy so previously assigned
            # unitTo{Before,After}Flow are not affected
            IN_wip = deepcopy(IN_wip)
            self.gen_IN(instr, free_var, IN_wip)
        else:
            # other calls
            IN_wip = self.handle_other_call(instr, IN_wip, dest_var)
        return IN_wip

    def handle_other_call(
            self, instr: binaryninja.highlevelil.HighLevelILCall,
            IN_wip: Dict[str, set[int]],
            dest_var: Optional[binaryninja.variable.Variable] = None
    ) -> Dict[str, set[int]]:
        #
        callee_addr = instr.dest.value.value
        callee_func = self.bv.get_function_at(callee_addr)
        if callee_func in self.func_summaries:
            callee_sum: Summary = self.func_summaries[callee_func]
            if dest_var is not None and callee_sum.ret_free:
                self.gen_IN(instr, dest_var, IN_wip)
            if callee_func is not None:
                callee_params = callee_func.parameter_vars.vars
                for i, arg_is_free in enumerate(callee_sum.args_free):
                    if arg_is_free:
                        self.gen_IN(instr, callee_params[i], IN_wip)

        # over-approximate. If IN_wip overlaps with params, alert
        for param in instr.params:
            param = cast(binaryninja.highlevelil.HighLevelILVar, param)
            if param.operation.name != "HLIL_VAR":
                continue
            self.update_args_use_sum(param.var)
            if param.var.name in IN_wip.keys():
                # param is free'd already
                self.update_reporter(instr, param.var, IN_wip,
                                     "use-after-free")
            elif len(IN_wip) != 0:
                # alias query of free_var with each dataflow fact in IN_wip
                # check if param's alias is free'd already
                for in_var in IN_wip.keys():
                    if self.alias.is_alias(param.var.name, in_var,
                                           instr.instr_index):
                        self.update_reporter(instr, param.var, IN_wip,
                                             "use-after-free", True)

        return IN_wip

    def update_args_use_sum(self, _var: binaryninja.variable.Variable) -> None:
        if _var in self.args:
            arg_index = self.args.index(_var)
            self.args_use_sum[arg_index] = True

    def update_args_free_sum(self, _var: binaryninja.variable.Variable) -> None:
        if _var in self.args:
            arg_index = self.args.index(_var)
            self.args_free_sum[arg_index] = True

    def update_ret_free_sum(
            self, instr: binaryninja.highlevelil.HighLevelILRet,
            IN_wip: Dict[str, set[int]]
    ) -> None:
        for var in instr.vars:
            if var.name in IN_wip.keys():
                # return value is free'd
                self.ret_free_sum = True
                break

    def is_free(self, instr: binaryninja.highlevelil.HighLevelILCall) -> bool:
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
                # happen to have same name as a deallocation method
                return False
            return True
        # function name not a deallocation name
        return False

    @staticmethod
    def gen_IN(
            instr: binaryninja.highlevelil.HighLevelILInstruction,
            var: binaryninja.variable.Variable, IN: Dict[str, set[int]]
    ) -> None:
        """Update dataflow facts"""
        if var.name in IN.keys():
            IN[var.name].add(instr.instr_index)
        else:
            IN[var.name] = {instr.instr_index}

    @staticmethod
    def new_initial_flow() -> Dict:
        """Initial dataflow container which is a dict"""
        return dict()

    @staticmethod
    def merge(in1, in2):
        """Combine two sets since the abstract domain is the powerset lattice"""
        out1 = deepcopy(in1)
        out2 = deepcopy(in2)
        # MAY analysis
        return out1 | out2

    def update_reporter(
            self, instr: binaryninja.highlevelil.HighLevelILInstruction,
            var: binaryninja.variable.Variable, IN: Dict[str, set[int]],
            vuln_type: str, isAlias=False
    ) -> None:
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


def get_danglers(bv: binaryninja.binaryview.BinaryView) -> Dict[str, int]:
    """identify deallocation methods that create dangling ptr from symbol table"""
    # if not in symbol table, the binary does not call free anywhere
    dangling_creators = dict()
    free_syms = ["free", "_free"]

    for free_sym in free_syms:
        if free_sym in bv.symbols:
            # identify the imported function address for free
            free = bv.symbols[free_sym]
            if free is None:
                continue
            free_addr = None
            for sym in free:
                if sym.type.name == "ImportedFunctionSymbol":
                    free_addr = sym.address
                    break
            if isinstance(free_addr, int):
                dangling_creators[free_sym] = free_addr
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
    # create function summaries
    # create unit tests and CI/CD
    vuln_lines = set()
    cg = core.Callgraph(bv)
    rto = core.rto_traversal(cg)
    for func in rto:
        # if func.name != "Java_com_example_hellolibs_NativeCall_echoJNI":
        #     continue
        print(f"    func({hex(func.start)}): {func.name}")
        vulns = VulnsDetector(func, bv, dangling_creators)
        # breakpoint()
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
