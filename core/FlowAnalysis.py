from abc import ABC, abstractmethod


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
