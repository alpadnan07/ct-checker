import angr
import claripy
import inspect
import pdb
import sys
import os
sys.path.append(os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)),'memsight')))
from memory import factory
def inspect_function(f):
    import inspect
    print(inspect.getfile(f))
    print(inspect.getsource(f))


def act_memory_write(state):
    if str(state.inspect.mem_write_address) == '<BV64 0xcafebabe>':
        print('WRITE',state.inspect.mem_write_address,state.inspect.mem_write_expr,state.inspect.mem_write_expr.annotations)
def act_register_write(state):
        if str(state.inspect.reg_write_expr) == "<BV64 0#32 .. (0#24 .. high_0_8)>":
            print(state.inspect.reg_write_expr.args[1].args[1].annotations)
            print('WRITE REG',state.inspect.reg_write_offset,state.inspect.reg_write_expr,state.inspect.reg_write_expr.annotations)
            # pdb.set_trace()
def act_register_write_after(state):
    return
    if state.inspect.reg_write_offset==16:
        pdb.set_trace()
def act_register_read_before(state):
    return
    if state.inspect.reg_read_offset == 16:
        pdb.set_trace()

def act_register_read(state):
        try:
            print('READ REG',state.inspect.reg_read_offset,state.inspect.reg_read_expr,state.inspect.reg_read_expr.annotations)
        except:
            pass
def act_expr(state):
        expr = state.inspect.expr
        print('EXPAFTER',state.inspect.expr,)
        if   "high_0_8" in str(state.inspect.expr):
            print('ANNOT',state.inspect.expr.annotations)
            # pdb.set_trace()

def act_memory_read_after(state):
    print()
    if str(state.inspect.mem_read_address) == '<BV64 0xdeadbeef>':
        print('READ',state.inspect.mem_read_address,state.inspect.mem_read_expr,state.inspect.mem_read_expr.annotations)





project = angr.Project("./scratch")
mem_memory,_ = factory.get_range_fully_symbolic_memory(project)


state = project.factory.entry_state(plugins={'memory':mem_memory})
state.inspect.b('mem_write',when=angr.BP_BEFORE, action=act_memory_write)
state.inspect.b('reg_write',when=angr.BP_BEFORE, action=act_register_write)
state.inspect.b('reg_write',when=angr.BP_AFTER, action=act_register_write_after)

state.inspect.b('reg_read',when=angr.BP_AFTER, action=act_register_read)
state.inspect.b('reg_read',when=angr.BP_BEFORE, action=act_register_read_before)

state.inspect.b('expr',when=angr.BP_AFTER,action=act_expr)

state.inspect.b('mem_read',when=angr.BP_AFTER, action=act_memory_read_after)

sym_ann = state.se.BVS("high",8)
sym_ann = sym_ann.annotate(claripy.Annotation())
print(sym_ann.annotations)
state.memory.store(0xdeadbeef,sym_ann)
sm = project.factory.simulation_manager(state)
sm.run()
sm.step()

sm.step()

print(sm.stashes)

# init = sm.deadended[0].memory.load(0xdeadbeef,1)
res = sm.deadended[0].memory.load(0xcafebabe,1)
print(res,res.annotations)
# print(state.memory.load(0xdeadbeef,1).annotations)