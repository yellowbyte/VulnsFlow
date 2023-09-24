from copy import deepcopy

from core import FlowAnalysis


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
