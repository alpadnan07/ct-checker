import claripy
import angr
import pdb
import sys
import os
import logging

sys.path.append(os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)),'memsight')))
from memory import factory

HIGH_MEMORY_START = 0xcafebabe
LOW_MEMORY_START = 0xdeadbeef
MEMORY_RANGE_SIZE_BIT = 64

HIGH_BIT = claripy.true
LOW_BIT = claripy.false

EXIT_CT = 0
EXIT_NOT_CT = 1
# class NonConstantTimeError(Exception):
#     """Exception raised for errors in the non-constant time operation."""
#     def __init__(self, message="Non-constant time operation detected."):
#         super(NonConstantTimeError, self).__init__(message)
#         self.message = message


def ct_check_binary(binary_path):

    l = logging.getLogger("angr.engines.successors")
    l.setLevel(logging.ERROR)

    project = angr.Project(binary_path)
    # import pdb
    # pdb.set_trace()

    mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(project)
    plugins = {'memory': mem_memory}
    initial_state = project.factory.entry_state(plugins=plugins)
    initial_state = ct_get_checked_state(initial_state)
    # TODO add veritesting boundaries, or get rid of veritesting, what do boundaries even do? idk?
    # TODO Would I like to try memsight for registers?
    # TODO Replace name based taint with annotations, name based taint is clearly broken
    sm = project.factory.simulation_manager(initial_state, save_unconstrained=True,veritesting=True, save_unsat=False)
    sm.run()
    sys.exit(EXIT_CT)
    


def ct_get_checked_state(state):
    high_var = claripy.BVS("_HIGH_high",MEMORY_RANGE_SIZE_BIT)
    low_var = claripy.BVS("low",MEMORY_RANGE_SIZE_BIT)
    state.se.simplify(high_var)    
    state.memory.store(HIGH_MEMORY_START,high_var)
    
    state.memory.store(LOW_MEMORY_START,low_var)
    state.inspect.b('mem_read',when=angr.BP_BEFORE,action=act_memory_read)
    state.inspect.b('mem_write',when=angr.BP_BEFORE,action=act_memory_write)
    state.inspect.b('exit',when=angr.BP_BEFORE,action=act_exit)
    return state 


def act_memory_read(state):
    read_address = state.inspect.mem_read_address

    assert type(read_address) in (int,long, claripy.ast.bv.BV)

    if type(read_address) is claripy.ast.bv.BV and read_address.op != "BVV" and state.satisfiable(extra_constraints=[ct_formula(read_address)]):
        # TODO it is a bit weird to exit. maybe i want a better interface?
        sys.exit(EXIT_NOT_CT)
        # raise NonConstantTimeError("Non CT READ")

def act_memory_write(state):
    write_address = state.inspect.mem_write_address
    assert type(write_address) in (int,long, claripy.ast.bv.BV)

    if type(write_address) is claripy.ast.bv.BV and write_address.op != "BVV" and  state.satisfiable(extra_constraints=[ct_formula(write_address)]):
        # raise NonConstantTimeError("Non CT WRITE")
        sys.exit(EXIT_NOT_CT)

def act_exit(state):
    exit_guard = state.inspect.exit_guard

    if type(exit_guard) is  claripy.ast.bool.Bool and exit_guard.op != "BoolV" and  state.satisfiable(extra_constraints=[ct_formula(exit_guard)]):
        sys.exit(EXIT_NOT_CT)

def ct_formula(symbolic_addr):
    # TODO It is crucial to check how constraints are handled
    # For example something like:
    # a <- tainted_sym
    # b <- fresh_sym
    # ADD CONSTRAINT a = b
    # if(b)...
    # would break ct_formula(),
    # though it shouldnt be possible for angr to
    # randomly add conditions of that kind without a
    # proper statement. Will think about that
    # maybe memsight might have some funny extra constraint adding mechanism?
    if type(symbolic_addr) in (int,long,bool):
        return LOW_BIT

    op = symbolic_addr.op
    args = symbolic_addr.args
    
    if op == 'If':
        cond = args[0]
        exp_true = args[1]
        exp_false = args[2]
        return claripy.Or(claripy.If(cond,ct_formula(exp_true),ct_formula(exp_false)), ct_formula(cond))
    elif op in ['BVV','BoolV'] :
        return LOW_BIT
    elif op == 'BVS':
        # i might want to fix that random garbage
        return HIGH_BIT if symbolic_addr.args[0].startswith("_HIGH_") else LOW_BIT
    else:
        ct_args = [ct_formula(arg) for arg in args]
        #check if any argument is high
        for arg in ct_args:
            if arg.structurally_match(HIGH_BIT):
                return HIGH_BIT

        might_be_high = [arg for arg in ct_args if not arg.structurally_match(LOW_BIT)]
        return LOW_BIT if len(might_be_high) == 0 else claripy.Or(*might_be_high)

def inspect_function(f):
    import inspect
    print(inspect.getfile(f))
    print(inspect.getsource(f))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python {} <binary_path>".format(sys.argv[0]))
        sys.exit(1)
    
    binary_path = sys.argv[1]
    ct_check_binary(binary_path)
