from copy import deepcopy
from abc import ABC, abstractmethod

import binaryninja
import sys
import os


class FlowAnalysis(ABC):

    def __init__(self, method_ir, direction):
        # default
        self.unitToBeforeFlow = dict()
        self.unitToAfterFlow = dict()

        # analysis/method specific
        self.method_ir = method_ir
        self.direction = direction
        self.do_analysis()

    def do_analysis(self):
        """Iterative worklist solver"""
        if self.method_ir is None:
            # IL the worklist operates in does not exist for `method`
            return
        bbs = self.method_ir.basic_blocks

        # initial dataflow facts        
        OUTs = list()  # track dataflow at end of each basic block
        for i in range(len(bbs)):
            OUTs.append(self.new_initial_flow())

        # every basic block is added to worklist at the beginning
        worklist = list()
        for bb in bbs:
            worklist.append(bb)

        # solver's fixpoint iteration
        while len(worklist) != 0:
            curr_bb = worklist.pop(0)
            bb_instrs = [i for i in curr_bb]
            if self.direction != "forward":
                bb_instrs = reversed(bb_instrs)
            IN = self.new_initial_flow()
            # merge
            # currently hardcoded to forward analysis
            for bb in self.flow_direction(curr_bb, True):
                IN = self.merge(IN, OUTs[bb.index])
            # flow block function
            OUT = self.flow_through(bb_instrs, IN)
            # update worklist if OUT change
            if OUTs[curr_bb.index] != OUT:
                OUTs[curr_bb.index] = OUT
                # add all successors to worklist
                for bb in self.flow_direction(curr_bb, False):
                    worklist.append(bb)

    def flow_direction(self, bb, is_flow_in):
        """Iterate basic blocks with respect to `bb` flow direction"""
        if self.direction == "forward":
            if is_flow_in:
                edges = bb.incoming_edges
                is_incoming = True
            else:
                edges = bb.outgoing_edges
                is_incoming = False
        else:  # backward
            if is_flow_in:
                edges = bb.outgoing_edges
                is_incoming = False
            else:
                edges = bb.incoming_edges
                is_incoming = True

        for edge in edges:
            if is_incoming:
                yield edge.source
            else:
                yield edge.target

    def flow_before_index(self, instr_index):
        """Flow before getter by instruction index"""
        return self.unitToBeforeFlow[instr_index]

    def flow_after_index(self, instr_index):
        """Flow after getter by instruction index"""
        return self.unitToAfterFlow[instr_index]

    def flow_before(self, instr):
        """Flow before getter by instruction"""
        return self.unitToBeforeFlow[instr.instr_index]

    def flow_after(self, instr):
        """Flow after getter by instruction"""
        return self.unitToAfterFlow[instr.instr_index]

    @abstractmethod
    def flow_through(self, bb, IN):
        """Flow functions implementation"""
        pass

    @staticmethod
    @abstractmethod
    def new_initial_flow():
        """Dataflow facts' container"""
        pass

    @staticmethod
    @abstractmethod
    def merge(in1, in2):
        """Dataflow confluence operator"""
        pass


class MayAlias(FlowAnalysis):

    def __init__(self, method):
        super().__init__(method.hlil, "forward")

    def flow_through(self, bb, IN):
        """Fact-affecting flow functions for may alias"""
        IN_wip = deepcopy(IN)
        for instr in bb:
            self.unitToBeforeFlow[instr.instr_index] = IN_wip
            if instr.operation.name == "HLIL_VAR_INIT":
                instr_src = instr.src
                if instr_src.operation.name == "HLIL_CALL":
                    IN_wip = deepcopy(IN_wip)
                    runtime_obj = instr.dest
                    self.add_new_alias(runtime_obj, IN_wip)
                if instr_src.operation.name == "HLIL_VAR":
                    IN_wip = deepcopy(IN_wip)
                    alias_dest = instr.dest
                    alias_src = instr_src.var
                    self.update_aliases(alias_dest, alias_src, IN_wip)
            self.unitToAfterFlow[instr.instr_index] = IN_wip
        OUT = IN_wip
        return OUT

    @staticmethod
    def update_aliases(alias_dest, alias_src, IN):
        """Update existing runtime objects' aliases"""
        # add runtime objs containing alias_dest to runtime objs containing alias_src
        objs_containing_dest = list()
        IN_cp = deepcopy(IN)
        for obj in IN_cp:
            if alias_dest.name in obj:
                objs_containing_dest.append(obj)
        if len(objs_containing_dest) == 0:
            objs_containing_dest.append({alias_dest.name})
        for obj in IN_cp:
            if alias_src.name in obj:
                for dest_obj in objs_containing_dest:
                    new_obj = obj.union(dest_obj)
                    IN.remove(obj)
                    IN.append(new_obj)

    @staticmethod
    def add_new_alias(var, IN):
        """Create new runtime object"""
        IN_cp = deepcopy(IN)
        # remove runtime obj with var
        for obj in IN_cp:
            if var.name in obj:
                IN.remove(obj)
        # add new runtime obj
        IN.append({var.name})

    @staticmethod
    def merge(in1, in2):
        """Combine two lists of runtime objects where each object is a set"""
        out1 = deepcopy(in1)
        out2 = deepcopy(in2)
        out_combined = list()
        # MAY analysis
        for obj in out1:
            if obj not in out_combined:
                out_combined.append(obj)
        for obj in out2:
            if obj not in out_combined:
                out_combined.append(obj)
        return out_combined

    @staticmethod
    def new_initial_flow():
        """Initial dataflow container which is a list"""
        return list()

    def is_alias(self, var1, var2, instr_index):
        """
        Alias query

        :rtype: Boolean
        """
        # set of sets where each set represents a runtime object
        flowset = self.flow_before_index(instr_index)
        alias_obj = {var1, var2}
        for obj in flowset:
            if len(obj.intersection(alias_obj)) == 2:
                # var1 and var2 alias
                return True
        # var1 and var2 do not alias
        return False


class VulnsDetector(FlowAnalysis):

    def __init__(self, method, lib_methods=None):
        self.method = method
        self.lib_methods = lib_methods
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
                assert "free" in self.lib_methods.keys()
                if callee_addr == self.lib_methods["free"]:
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
    required_methods = dict()
    required_methods["free"] = free_addr

    for func in bv.functions:
        #        if func.name != "_main":
        #            continue
        print("    func:" + func.name)
        vulns = VulnsDetector(func, required_methods)
        # output vulns identified
        if len(vulns.reporter) != 0:
            #            breakpoint()
            for vuln in vulns.reporter:
                output_file.write(vuln)
                output_file.flush()

    output_file.close()
