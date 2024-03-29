import angr
import logging
import claripy
import pdb
import sys
import os
import pyvex
import traceback
import bisect
import cffi
import resource
import pdb
import time

# our stuff
from angr.state_plugins import SimActionObject, SimStateHistory
from memory.lib import paged_memory, sorted_collection, unpaged_memory
from memory.lib.pitree import pitree, untree
from utils import get_obj_byte, reverse_addr_reg, get_unconstrained_bytes, convert_to_ast, full_stack, \
    resolve_location_name

log = logging.getLogger('memsight')
log.setLevel(logging.DEBUG)

# profiling vars
time_profile = {}
total_time = 0
last_dump_time = 0
count_ops = 0

profiling_enabled = False

def update_counter(elapsed, f):

    global profiling_enabled
    global time_profile
    global count_ops
    global total_time
    global last_dump_time

    if not profiling_enabled: return

    if f not in time_profile:
        time_profile[f] = [1, elapsed]
    else:
        time_profile[f][0] += 1
        time_profile[f][1] += elapsed

    total_time += elapsed
    count_ops += 1

    if total_time > 30:
        #print "Executing " + str(f)
        pass

    if count_ops > 0 and (count_ops % 10000 == 0 or (total_time - last_dump_time>10)):
        print_profiling_time_stats()
        last_dump_time = total_time

def print_profiling_time_stats(depth=None, pg=None):
    print
    print "Profiling stats" + ("at depth=" + str(depth) if depth is not None else "") + ":"
    print
    for ff in time_profile:
        print "\t" + str(ff) + ": ncall=" + str(time_profile[ff][0]) + " ctime=" + str(time_profile[ff][1])
    print
    print


def profile(func):
    def wrap(*args, **kwargs):
        import time
        started_at = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - started_at
        update_counter(elapsed, func.__name__)
        return result

    return wrap


class MemoryItem(object):
    __slots__ = ('addr', '_obj', 't', 'guard')

    def __init__(self, addr, obj, t, guard):
        self.addr = addr
        self._obj = obj
        self.t = t
        self.guard = guard

    @property
    def obj(self):
        if type(self._obj) in (list,):
            self._obj = get_obj_byte(self._obj[0], self._obj[1])
        return self._obj

    def __repr__(self):
        return "[" + str(self.addr) + ", " + str(self.obj) + ", " + str(self.t) + ", " + str(self.guard) + "]"

    # noinspection PyProtectedMember
    def _compare_obj(self, other):

        if id(self._obj) == id(other._obj):
            return True

        if type(self._obj) in (list,) and type(other._obj) in (list,) \
                and id(self._obj[0]) == id(other._obj[0]) \
                and self._obj[1] == self._obj[1]:
            return True

        if type(self._obj) in (list,):
            if type(self._obj[0]) not in (claripy.ast.bv.BV,):
                return False
        elif type(self._obj) not in (claripy.ast.bv.BV,):
            return False

        if type(other._obj) in (list,):
            if type(other._obj[0]) not in (claripy.ast.bv.BV,):
                return False
        elif type(other._obj) not in (claripy.ast.bv.BV,):
            return False

        a = self.obj
        b = other.obj
        if a.op == 'BVV' and b.op == 'BVV':
            return a.args[0] == b.args[0]

        return False

    def __eq__(self, other):

        if id(self) == id(other):
            return True

        if (other is None
            or self.t != other.t
            # or (type(self.addr) in (int, long) and type(other.addr) in (int, long) and self.addr != other.addr)
            or (type(self.obj) in (int, long) and type(other.obj) in (int, long) and self.obj != other.obj)
            or id(self.guard) != id(other.guard)  # conservative
            or not self._compare_obj(other)):
            return False

        return True

    def copy(self):
        return MemoryItem(self.addr, self.obj, self.t, self.guard)


class MappedRegion(object):
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4

    def __init__(self, addr, length, permissions):
        self.addr = addr
        self.length = length
        self.permissions = permissions

    def __repr__(self):
        rwx_s = "r" if self.is_readable() else ''
        rwx_s += "w" if self.is_writable() else ''
        rwx_s += "x" if self.is_executable() else ''
        return "(" + str(hex(self.addr)) + ", " + str(hex(self.addr + self.length)) + ") [" + rwx_s + "]"

    def is_readable(self):
        return self.permissions.args[0] & MappedRegion.PROT_READ

    def is_writable(self):
        return self.permissions.args[0] & MappedRegion.PROT_WRITE

    def is_executable(self):
        return self.permissions.args[0] & MappedRegion.PROT_EXEC


class SymbolicMemory(angr.state_plugins.plugin.SimStatePlugin):
    @profile
    def __init__(self, memory_backer=None,
                 permissions_backer=None,
                 kind=None,
                 arch=None,
                 endness=None,
                 check_permissions=None,
                 concrete_memory=None,
                 symbolic_memory=None,
                 stack_range=None,
                 mapped_regions=[],
                 verbose=False,
                 timestamp=0,
                 initializable=None,
                 initialized=False,
                 timestamp_implicit=0,
                 angr_memory=None,
                 debug_with_angr=False,
                 profiling=False):

        angr.state_plugins.plugin.SimStatePlugin.__init__(self)

        self._memory_backer = memory_backer
        # assert not permissions_backer[0]
        self._permissions_backer = permissions_backer
        self._id = kind
        self._arch = arch
        self._endness = "Iend_BE" if endness is None else endness

        self._initial_timestamps = [timestamp, timestamp_implicit]

        self._concrete_memory = paged_memory.PagedMemory(self) if concrete_memory is None else concrete_memory
        #self._concrete_memory = unpaged_memory.PagedMemory(self) if concrete_memory is None else concrete_memory

        self._symbolic_memory = pitree.pitree() if symbolic_memory is None else symbolic_memory
        #self._symbolic_memory = untree.Untree() if symbolic_memory is None else symbolic_memory

        # some threshold
        self._maximum_symbolic_size = 8 * 1024
        self._maximum_concrete_size = 0x1000000

        self._abstract_backer = None

        # stack range
        self._stack_range = stack_range

        # mapped regions
        self._mapped_regions = mapped_regions

        self.verbose = verbose
        if self.verbose: self.log("symbolic memory has been created")

        self._initializable = initializable if initializable is not None else sorted_collection.SortedCollection(
            key=lambda x: x[0])
        self._initialized = initialized

        # required by CGC deallocate()
        self._page_size = self._concrete_memory.PAGE_SIZE

        global profiling_enabled
        profiling_enabled = profiling

        self.angr_memory = angr_memory
        if self.angr_memory is None and debug_with_angr:
            self.angr_memory = angr.state_plugins.SimSymbolicMemory(memory_backer=memory_backer, permissions_backer=permissions_backer, memory_id='mem')

    @property
    def timestamp(self):
        assert self.state is not None
        self.init_timestamps()
        return self.state.history.timestamps[0]

    @timestamp.setter
    def timestamp(self, value):
        assert self.state is not None
        self.init_timestamps()
        self.state.history.timestamps[0] = value

    @property
    def implicit_timestamp(self):
        assert self.state is not None
        self.init_timestamps()
        return self.state.history.timestamps[1]

    @implicit_timestamp.setter
    def implicit_timestamp(self, value):
        assert self.state is not None
        self.init_timestamps()
        self.state.history.timestamps[1] = value

    def init_timestamps(self):
        assert self.state is not None
        if self._initial_timestamps is not None:
            self.state.history.timestamps = self._initial_timestamps
            self._initial_timestamps = None

    @property
    def _pages(self):
        # required by CGC deallocate()
        # this is not correct
        return self._concrete_memory._pages

    def _init_memory(self):

        if self._initialized:
            return

        # init mapped regions
        for start, end in self._permissions_backer[1]:
            perms = self._permissions_backer[1][(start, end)]
            self.map_region(start, end - start, perms, internal=True)

        # init memory
        if self._memory_backer is not None:

            _ffi = cffi.FFI()
            for addr, backer in self._memory_backer.cbackers:

                data = _ffi.buffer(backer)[:]
                obj = claripy.BVV(data)

                page_size = 0x1000
                size = len(obj) / 8
                data_offset = 0
                page_index = int(addr / page_size)
                page_offset = addr % page_size

                if self.verbose:
                    self.log("Pre-defined memory region: addr=" +  hex(addr) + " size=" + str(size))

                while size > 0:

                    max_bytes_in_page = page_index * 0x1000 + 0x1000 - addr
                    mo = [page_index, obj, data_offset, page_offset, min([size, page_size, max_bytes_in_page])]
                    if self.verbose: self.log("Adding initializable area: page_index=" + str(mo[0]) + " size=" + str(
                        mo[4]) + " data_offset=" + str(mo[2]))
                    self._initializable.insert(mo)
                    page_index += 1
                    size -= page_size - page_offset
                    data_offset += page_size - page_offset
                    page_offset = 0

        """
        # force load initialized bytes at the startup
        indexes = set(self._initializable._keys)
        for index in indexes:
            self._load_init_data(index * 0x1000, 1)

        assert len(self._initializable._keys) == 0
        """

        self._initialized = True

    @profile
    def set_state(self, state):
        if self.verbose: self.log("setting current state...")
        self.state = state
        self._init_memory()

        if self.angr_memory is not None:
            add_strategies = self.angr_memory.write_strategies is None
            self.angr_memory.set_state(state)
            if add_strategies:
                # print "Adding strategies..."
                self.angr_memory.write_strategies.insert(0,
                                                         angr.concretization_strategies.SimConcretizationStrategyRange(
                                                             1024 * 100))
                self.angr_memory.read_strategies.insert(0,
                                                        angr.concretization_strategies.SimConcretizationStrategyRange(
                                                            1024 * 100))

    @profile
    def _load_init_data(self, addr, size):

        page_size = 0x1000
        page_index = int(addr / page_size)
        page_end = int((addr + size) / page_size)
        k = bisect.bisect_left(self._initializable._keys, page_index)

        if self.verbose: self.log(
            "\tChecking initializable: page index " + str(page_index) + " k=" + str(k) + " max_k=" + str(
                len(self._initializable)) + " end_k=" + str(page_end))

        to_remove = []
        while k < len(self._initializable) and self._initializable[k][0] <= page_end:

            data = self._initializable[k]  # [page_index, data, data_offset, page_offset, min(size, page_size]
            if self.verbose: self.log("\tLoading initialized data at " + str(data[0])) # + " => " + str(data))
            page = self._concrete_memory._pages[data[0]] if data[0] in self._concrete_memory._pages else None
            for j in range(data[4]):

                if page is not None and data[3] + j in page:
                    continue

                e = (data[0] * 0x1000) + data[3] + j
                v = [data[1], data[2] + j]
                self._concrete_memory[e] = MemoryItem(e, v, 0, None)

            to_remove.append(data)
            k += 1

        for e in to_remove:
            self._initializable.remove(e)

        if len(to_remove):
            if self.verbose: self.log("\tRemaining items in initializable: " + str(len(self._initializable)))

    @profile
    def _raw_ast(self, a):
        if type(a) is angr.state_plugins.sim_action_object.SimActionObject:
            return a.ast
        elif type(a) is dict:
            return {k: self._raw_ast(a[k]) for k in a}
        elif type(a) in (tuple, list, set, frozenset):
            return type(a)((self._raw_ast(b) for b in a))
        else:
            return a

    @profile
    def memory_op(self, addr, size, data=None, op=None):

        addr = self._raw_ast(addr)
        size = self._raw_ast(size)
        data = self._raw_ast(data)

        if op == 'store':
            data = self._convert_to_ast(data, size if isinstance(size, (int, long)) else None)

        reg_name = None
        if self._id == 'reg':

            if type(addr) in (int, long):
                reg_name = reverse_addr_reg(self, addr)
                if self.verbose: self.log("\t" + str(addr) + " => " + str(reg_name))

            if isinstance(addr, basestring):
                reg_name = addr
                addr, size_reg = resolve_location_name(self, addr)
                if self.verbose: self.log("\t" + str(addr) + " => " + str(reg_name))

                # a load from a register, derive size from reg size
                if size is None:
                    size = size_reg
                    if self.verbose: self.log("\tsize => " + str(size))

                assert size_reg == size

            assert reg_name is not None

        # if this is a store then size can be derived from data that needs to be stored
        if size is None and type(data) in (claripy.ast.bv.BV, claripy.ast.fp.FP):
            size = len(data) / 8
            assert type(size) in (int, long)
            if self.verbose: self.log("\tsize => " + str(size))

        # convert size to BVV if concrete
        if type(size) in (int, long):
            size = self.state.se.BVV(size, self.state.arch.bits)

        if op == 'load' and size is None:
            size = self.state.arch.bits / 8

        # make size concrete
        if size is not None:
            _, _, size = self._resolve_size(size, op)

        # if addr is constant, make it concrete
        if type(addr) in (claripy.ast.bv.BV,) and not addr.symbolic:
            addr = addr.args[0]

        if size is None:
            # print "Size is None. type(data): " + str(type(data))
            # pdb.set_trace()
            pass

        assert size is not None
        if self._id == 'reg':
            assert type(addr) in (int, long)

        return addr, size, reg_name

    @profile
    def build_ite(self, addr, cases, v, obj):

        assert len(cases) > 0

        if len(cases) == 1:
            cond = addr == cases[0].addr
        else:
            cond = self.state.se.And(addr >= cases[0].addr, addr <= cases[-1].addr)

        cond = claripy.And(cond, cases[0].guard) if cases[0].guard is not None else cond

        return self.state.se.If(cond, v, obj)

    @profile
    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False, internal=False, ignore_endness=False):
        angr_data = None
        if self.angr_memory is not None and not internal:
            angr_data = self.angr_memory.load(addr=addr, size=size, condition=condition, fallback=fallback,
                                              add_constraints=add_constraints, action=action, endness=endness,
                                              inspect=inspect)

        assert add_constraints is None

        # self.state.state_counter.log.append("[" + hex(self.state.regs.ip.args[0]) +"] " + "Loading " + str(size) + " bytes at " + str(addr))

        try:

            if self.verbose: self.log("Loading " + str(size) + " bytes.")

            assert self._id == 'mem' or self._id == 'reg'

            if condition is not None and self.state.se.is_false(condition):
                return

            addr, size, reg_name = self.memory_op(addr, size, op='load')

            if inspect is True:
                if self.category == 'reg':
                    self.state._inspect('reg_read', angr.BP_BEFORE, reg_read_offset=addr, reg_read_length=size)
                    addr = self.state._inspect_getattr("reg_read_offset", addr)
                    size = self.state._inspect_getattr("reg_read_length", size)
                elif self.category == 'mem':
                    self.state._inspect('mem_read', angr.BP_BEFORE, mem_read_address=addr, mem_read_length=size)
                    addr = self.state._inspect_getattr("mem_read_address", addr)
                    size = self.state._inspect_getattr("mem_read_length", size)

            try:
                assert not self.state.se.symbolic(size)
            except Exception as e:
                import pdb
                pdb.set_trace()

            if type(size) in (int, long):

                # concrete address
                if type(addr) in (int, long):
                    min_addr = addr
                    max_addr = addr

                # symbolic addr
                else:
                    min_addr = self.state.se.min_int(addr)
                    max_addr = self.state.se.max_int(addr)
                    if min_addr == max_addr:
                        addr = min_addr

                # check permissions
                self.check_sigsegv_and_refine(addr, min_addr, max_addr, False)

                # check if binary data should be loaded into address space
                self._load_init_data(min_addr, (max_addr - min_addr) + size)

                if angr_data is not None:
                    assert size == len(angr_data) / 8

                data = None
                for k in range(size):

                    if self.verbose: self.log("\tLoading from: " + str(hex(addr + k) if type(addr) in (long, int) else (addr + k)))
                    #if self.verbose: self.log("\tAddr = [" + str(hex(min_addr + k)) + ", " + str(hex(max_addr + k)) + "]")

                    P = self._concrete_memory.find(min_addr + k, max_addr + k, True)

                    P += [x.data for x in self._symbolic_memory.search(min_addr + k, max_addr + k + 1)]
                    P = sorted(P, key=lambda x: (x.t, (x.addr if type(x.addr) in (int, long) else 0)))

                    if self.verbose: self.log("\tMatching formulas:" + str(len(P)))
                    #if self.verbose: self.log("\tMatching formulas:" + str(P))

                    if min_addr == max_addr and len(P) == 1 and type(P[0].addr) in (long, int) and P[0].guard is None:
                        obj = P[0].obj

                    else:

                        name = "%s_%x" % (self.id, min_addr + k)
                        obj = get_unconstrained_bytes(self.state, name, 8, memory=self)

                        if (self.category == 'mem' and
                                    angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY not in self.state.options):

                            if self.verbose: self.log("\t\tDoing an implicit store...")

                            # implicit store...
                            self.implicit_timestamp -= 1
                            self._symbolic_memory.add(min_addr + k, max_addr + k + 1,
                                                      MemoryItem(addr + k, obj, self.implicit_timestamp, None))

                        if self.verbose: self.log("\tAdding ite cases: " + str(len(P)))
                        obj = self.build_merged_ite(addr + k, P, obj)

                    # concat single-byte objs
                    if self.verbose: self.log("\tappending data: ")# + str(obj))
                    data = self.state.se.Concat(data, obj) if data is not None else obj

                if condition is not None:
                    assert fallback is not None
                    condition = self._raw_ast(condition)
                    fallback = self._raw_ast(fallback)
                    data = self.state.se.If(condition, data, fallback)

                # fix endness
                endness = self._endness if endness is None else endness
                if not ignore_endness and endness == "Iend_LE":
                    # if self.verbose: self.log("\treversing data: " + str(data))
                    data = data.reversed

                if inspect is True:
                    if self.category == 'mem':
                        self.state._inspect('mem_read', angr.BP_AFTER, mem_read_expr=data)
                        data = self.state._inspect_getattr("mem_read_expr", data)
                    elif self.category == 'reg':
                        self.state._inspect('reg_read', angr.BP_AFTER, reg_read_expr=data)
                        data = self.state._inspect_getattr("reg_read_expr", data)

                if not disable_actions and self.angr_memory is None:
                    if angr.options.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:
                        ref_size = size * self.state.arch.byte_width if size is not None else data.size()
                        region_type = self.category
                        if region_type == 'file':
                            # Special handling for files to keep compatibility
                            # We may use some refactoring later
                            region_type = self.id
                        action = angr.state_plugins.SimActionData(self.state, region_type,
                                                                  'write', addr=addr, data=data,
                                                                    size=ref_size,
                                                                    condition=condition)
                        self.state.history.add_action(action)

                    if action is not None:
                        action.actual_addrs = addr
                        action.actual_value = action._make_object(data)  # TODO
                        #if len(request.constraints) > 0:
                        #    action.added_constraints = action._make_object(self.state.se.And(*request.constraints))
                        #else:
                        action.added_constraints = action._make_object(self.state.se.true)

                if self.verbose: self.log("\treturning data ")# + str(data))

                if angr_data is not None:
                    assert len(data) == len(angr_data)
                    for k in range(len(data) / 8):
                        b1 = data[(8 * (k + 1)) - 1: (8 * k)]
                        b2 = angr_data[(8 * (k + 1)) - 1: (8 * (k))]
                        comparison, v1, v2 = self._compare_bytes(b1, b2)
                        if not comparison:
                            print "Mismatch at offset " + str(k)
                            import pdb
                            pdb.set_trace()

                return data

            assert False

        except Exception as e:

            if type(e) in (angr.errors.SimSegfaultError,):
                raise e

            print str(e)
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def build_merged_ite(self, addr, P, obj):

        #op_start_time = time.time()
        #print "Elapsed time: " + str(time.time() - op_start_time)

        N = len(P)
        merged_p = []
        for i in range(N):

            p = P[i]
            v = p.obj

            is_good_candidate = type(p.addr) in (int, long) and p.guard is None
            mergeable = False

            if len(merged_p) > 0 and is_good_candidate \
                    and p.addr == merged_p[-1].addr + 1:

                prev_v = merged_p[-1].obj
                if v.op == 'BVV':

                    # both constant and equal
                    if prev_v.op == 'BVV' and v.args[0] == prev_v.args[0]:
                        # if self.verbose: self.log("\tmerging ite with same constant and consecutive address")
                        mergeable = True

                # same symbolic object
                elif v is prev_v:
                    # if self.verbose: self.log("\tmerging ite with same sym and consecutive address")
                    mergeable = True

            if not mergeable:

                if len(merged_p) > 0:
                    #if self.verbose: self.log("\tbuilding ite with " + str(len(merged_p)) + " case(s)")  # " + str(addrs))
                    obj = self.build_ite(addr, merged_p, merged_p[-1].obj, obj)
                    merged_p = []

                if is_good_candidate:
                    merged_p.append(p)
                else:
                    if self.verbose:
                        self.log("\tbuilding ite with " + str(1) + " case(s)")  # " + str(addrs))
                    obj = self.build_ite(addr, [p], v, obj)

            else:
                merged_p.append(p)

        if len(merged_p) > 0:
            if self.verbose: self.log("\tbuilding ite with " + str(len(merged_p)) + " case(s)")  #: "+ str(v))
            obj = self.build_ite(addr, merged_p, merged_p[-1].obj, obj)

        return obj

    @profile
    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False, ignore_endness=False, internal=False):

        if not internal:
            #if self.verbose: self.log(str(self.state.ip) + " Storing at " + str(addr) + " " + str(size) + " bytes. Content: " + str(data))
            if self.verbose: self.log("Storing " + str(size) + " bytes.")  # Content: " + str(data))
            pass

        if priv is not None: self.state.scratch.push_priv(priv)

        if self.angr_memory is not None and not internal:
            self.angr_memory.store(addr=addr, data=data, size=size, condition=condition,
                                   add_constraints=add_constraints, action=action, endness=endness, inspect=inspect,
                                   priv=priv)

        assert add_constraints is None
        condition = self._raw_ast(condition)
        condition = self.state._adjust_condition(condition)

        try:

            assert self._id == 'mem' or self._id == 'reg'

            addr, size, reg_name = self.memory_op(addr, size, data, op='store')

            if inspect is True:
                if self.category == 'reg':
                    self.state._inspect(
                        'reg_write',
                        angr.BP_BEFORE,
                        reg_write_offset=addr,
                        reg_write_length=size,
                        reg_write_expr=data)
                    addr = self.state._inspect_getattr('reg_write_offset', addr)
                    size = self.state._inspect_getattr('reg_write_length', size)
                    data = self.state._inspect_getattr('reg_write_expr', data)
                elif self.category == 'mem':
                    self.state._inspect(
                        'mem_write',
                        angr.BP_BEFORE,
                        mem_write_address=addr,
                        mem_write_length=size,
                        mem_write_expr=data,
                    )
                    addr = self.state._inspect_getattr('mem_write_address', addr)
                    size = self.state._inspect_getattr('mem_write_length', size)
                    data = self.state._inspect_getattr('mem_write_expr', data)

            if condition is not None:
                if self.state.se.is_true(condition):
                    condition = None
                elif self.state.se.is_false(condition):
                    if priv is not None: self.state.scratch.pop_priv()
                    print condition
                    print "condition is false... skipping..."
                    return

            # store with conditional size
            conditional_size = None
            if self.state.se.symbolic(size):
                conditional_size = [self.state.se.min_int(size), self.state.se.max_int(size)]
                if self.verbose: "\tconditional-sized store: size=" + str(size) + " " + str(conditional_size)
                self.state.se.add(self.state.se.ULE(size, conditional_size[1]))

            # convert data to BVV if concrete
            data = convert_to_ast(self.state, data, size if isinstance(size, (int, long)) else None)

            if type(size) in (int, long) or conditional_size is not None:

                assert len(data) / 8 == (size if type(size) in (int, long) else conditional_size[1])

                # simplify
                data = self.state.se.simplify(data)

                # fix endness
                endness = self._endness if endness is None else endness
                if not ignore_endness and endness == "Iend_LE":
                    if not internal:
                        # if self.verbose: self.log("\treversing data: " + str(data))
                        pass
                    data = data.reversed
                    # if self.verbose: self.log("\treversed data: " + str(data))

                # concrete address
                if type(addr) in (int, long):
                    min_addr = addr
                    max_addr = addr

                # symbolic addr
                else:
                    min_addr = self.state.se.min_int(addr)
                    max_addr = self.state.se.max_int(addr)
                    if min_addr == max_addr:
                        addr = min_addr

                # check permissions
                self.check_sigsegv_and_refine(addr, min_addr, max_addr, True)

                self.timestamp += 1

                initial_condition = condition

                compilation_flag = 0

                for k in range(size if type(size) in (int, long) else conditional_size[1]):

                    compilation_flag += 1

                    obj = [data, k]
                    if type(size) in (int, long) and size == 1:
                        obj = data

                    if conditional_size is not None and k + 1 >= conditional_size[0]:
                        assert k + 1 <= conditional_size[1]
                        condition = self.state.se.UGT(size, k) if initial_condition is None else claripy.And(
                            initial_condition, self.state.se.UGT(size, k + 1))
                        if self.verbose: print "\tstore condition: " + str(condition)

                    if not internal:
                        if self.verbose: self.log("\tSlicing data with offset " + str(k))  # + " => " + str(obj))

                    inserted = False
                    constant_addr = min_addr == max_addr

                    if constant_addr:

                        assert addr == min_addr
                        P = self._concrete_memory[min_addr + k]
                        if P is None or condition is None:
                            if self.verbose: self.log("\tAdding/Updating concrete address...")
                            self._concrete_memory[min_addr + k] = MemoryItem(min_addr + k, obj, self.timestamp,
                                                                             condition)

                        else:
                            if self.verbose: self.log("\tAdding entry to existing concrete address: " + str(
                                len(P) if type(P) in (list,) else 1))
                            item = MemoryItem(min_addr + k, obj, self.timestamp, condition)
                            if type(P) in (list,):
                                P = [item] + P
                            else:
                                P = [item, P]
                            self._concrete_memory[min_addr + k] = P

                        inserted = True

                    if not inserted:

                        if condition is None:

                            P = self._symbolic_memory.search(min_addr + k, max_addr + k + 1)
                            if self.verbose: self.log("\tConflicting formulas: " + str(len(P)))
                            for p in P:
                                if id(p.data.addr) == id(addr + k):  # this check is pretty useless...
                                    if self.verbose: self.log("\tUpdating node...")
                                    self._symbolic_memory.update_item(p,
                                                                      MemoryItem(addr + k, obj, self.timestamp, None))
                                    inserted = True
                                    break

                    if not inserted:
                        if self.verbose: self.log("\tAdding node...")
                        self._symbolic_memory.add(min_addr + k, max_addr + k + 1,
                                                  MemoryItem(addr + k, obj, self.timestamp, condition))

                if self.verbose: self.log("returning")

                if inspect is True:
                    if self.category == 'reg': self.state._inspect('reg_write', angr.BP_AFTER)
                    if self.category == 'mem': self.state._inspect('mem_write', angr.BP_AFTER)

                if not disable_actions:
                    if angr.options.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:
                        ref_size = size * self.state.arch.byte_width if size is not None else data.size()
                        region_type = self.category
                        if region_type == 'file':
                            # Special handling for files to keep compatibility
                            # We may use some refactoring later
                            region_type = self.id
                        action = angr.state_plugins.SimActionData(self.state, region_type, 'write', addr=addr, data=data,
                                               size=ref_size,
                                               condition=condition
                                               )
                        self.state.history.add_action(action)

                    if action is not None:
                        action.actual_addrs = addr
                        action.actual_value = action._make_object(data)  # TODO
                        #if len(request.constraints) > 0:
                        #    action.added_constraints = action._make_object(self.state.se.And(*request.constraints))
                        #else:
                        action.added_constraints = action._make_object(self.state.se.true)

                if priv is not None: self.state.scratch.pop_priv()

                if self.angr_memory is not None:

                    try:
                        if self.verbose: print "Comparing..."

                        addrs = [x for x in range(min_addr, max_addr + self.state.se.max_int(size))]

                        """
                        addrs_sol = self.state.se.eval_upto(addr, 2048)
                        assert len(addrs_sol) < 2048

                        addrs = set()
                        for a in addrs_sol:
                            for k in range(self.state.se.max_int(size)):
                                addrs.add(a + k)
                        addrs = list(addrs)
                        """
                        self._compare_with_angr(addrs, op='store')

                    except Exception as e:
                        pdb.set_trace()

                return

            assert False

        except Exception as e:

            if type(e) in (angr.errors.SimSegfaultError,):
                raise e

            import traceback
            print str(e)
            traceback.print_exc()
            sys.exit(1)

    @profile
    def same(self, a, b, range_a=None, range_b=None):

        # true if the two formulas can cover exactly one address
        # I don't know if there could be other scenarios where this
        # can be true...

        if False and id(a) == id(b):
            return True
        try:
            cond = a != b
            return not self.state.se.satisfiable(extra_constraints=(cond,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def intersect(self, a, b, range_a=None, range_b=None):
        if id(a) == id(b):
            return True
        assert range_a is not None and range_b is not None
        if range_a is not None and range_b is not None and (range_a[1] < range_b[0] or range_b[1] < range_a[0]):
            return False

        try:
            cond = a == b
            return self.state.se.satisfiable(extra_constraints=(cond,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def disjoint(self, a, b, range_a=None, range_b=None):
        if id(a) == id(b):
            return False
        assert range_a is not None and range_b is not None
        if range_a is not None and range_b is not None and (range_a[1] < range_b[0] or range_b[1] < range_a[0]):
            return True

        try:
            cond = a == b
            return not self.state.se.satisfiable(extra_constraints=(cond,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def dump_memory(self):
        pass

    @profile
    def _resolve_size(self, size, op=None):

        if not self.state.se.symbolic(size):
            concrete_size = self.state.se.eval(size)
            if concrete_size > self._maximum_concrete_size:
                raise angr.SimMemoryLimitError("Concrete size %d outside of allowable limits" % concrete_size)
            return concrete_size, concrete_size, concrete_size

        max_size = self.state.se.max_int(size)
        min_size = self.state.se.min_int(size)

        if min_size != max_size:
            if op == 'load':  # we do not support, similarly to angr, symbolic size yet...
                log.warning("Concretizing symbolic length. Much sad; think about implementing.")
                self.state.add_constraints(size == max_size, action=True)
                size = max_size
        else:
            size = min_size

        if min_size > self._maximum_symbolic_size or max_size > self._maximum_symbolic_size:
            assert False  # ToDo

        return min_size, max_size, size

    def _convert_to_ast(self, data_e, size_e=None):
        """
        Make an AST out of concrete @data_e
        """
        if type(data_e) is str:
            # Convert the string into a BVV, *regardless of endness*
            bits = len(data_e) * 8
            data_e = self.state.se.BVV(data_e, bits)
        elif type(data_e) in (int, long):
            data_e = self.state.se.BVV(data_e, size_e * 8 if size_e is not None
            else self.state.arch.bits)
        else:
            data_e = data_e.to_bv()

        return data_e

    @property
    def category(self):

        res_angr = None
        if self.angr_memory is not None:
            res_angr = self.angr_memory.category

        if self._id in ('reg', 'mem'):
            assert res_angr is None or res_angr == self._id
            return self._id

    @profile
    def copy(self):

        if self.verbose: self.log("Copying memory")
        s = SymbolicMemory(memory_backer=self._memory_backer,
                           permissions_backer=self._permissions_backer,
                           kind=self._id,
                           arch=self._arch,
                           endness=self._endness,
                           check_permissions=None,
                           concrete_memory=self._concrete_memory,  # we do it properly below...
                           symbolic_memory=self._symbolic_memory.copy(),
                           stack_range=self._stack_range,
                           mapped_regions=self._mapped_regions[:],
                           verbose=self.verbose,
                           timestamp=self.timestamp,
                           initializable=self._initializable.copy(),
                           initialized=self._initialized,
                           timestamp_implicit=self.implicit_timestamp,
                           angr_memory=self.angr_memory.copy() if self.angr_memory is not None else None)

        s._concrete_memory = self._concrete_memory.copy(s)

        return s

    @property
    def id(self):

        res_angr = None
        if self.angr_memory is not None:
            res_angr = self.angr_memory.id

        assert res_angr is None or res_angr == self._id
        return self._id

    @property
    def mem(self):

        # In angr, this returns a reference to the (internal) paged memory
        # We do not have (yet) a paged memory. We instead return self
        # that exposes a _preapproved_stack attribute
        # (similarly as done by a paged memory)

        if self.angr_memory is not None:
            r = self.angr_memory.mem

        if self.verbose: self.log("getting reference to paged memory")
        return self

    @property
    def _preapproved_stack(self):

        res_angr = None
        if self.angr_memory is not None:
            res_angr = self.angr_memory.mem._preapproved_stack

        assert res_angr is None or res_angr == self._stack_range
        return self._stack_range

    @_preapproved_stack.setter
    def _preapproved_stack(self, value):
        if self.verbose: self.log(
            "Boundaries on stack have been set by the caller: (" + str(hex(value.start)) + ", " + str(
                hex(value.end)) + ")")

        if self.angr_memory is not None:
            self.angr_memory.mem._preapproved_stack = value

        if self._stack_range is not None:
            if self.verbose: self.log("\tUnnmapping old stack...")
            for k in range(len(self._mapped_regions)):
                region = self._mapped_regions[k]
                if region.addr == self._stack_range.start:
                    del self._mapped_regions[k]
                    if self.verbose: self.log("\tDone.")
                    break

        self._stack_range = value
        self.map_region(value.start, value.end - value.start, MappedRegion.PROT_READ | MappedRegion.PROT_WRITE)

    @profile
    def log(self, msg, verbose=True):
        if verbose:
            print("[" + self._id + "] " + msg)
            # l.debug("[" + self._id + "] " + msg)

    @profile
    def error(self, msg):
        log.error("[" + self._id + "] " + msg)

    def set_verbose(self, v):
        self.verbose = v

    @profile
    def is_verbose(self, v):
        self.verbose = v
        if not v:
            log.setLevel(logging.INFO)

    @profile
    def map_region(self, addr, length, permissions, internal=False):

        if self.angr_memory is not None and not internal:
            self.angr_memory.map_region(addr, length, permissions)

        if self.verbose: self.log("Required mapping of length " + str(length) + " at " + str(
            hex(addr if type(addr) in (long, int) else addr.args[0])) + ".")

        if hasattr(self.state, 'state_couner'):
            self.state.state_counter.log.append("[" + hex(self.state.regs.ip.args[0]) + "] " + "Map Region")

        if self.state.se.symbolic(addr) or self.state.se.symbolic(length):
            assert False

        # make if concrete
        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.max_int(addr)

        # make perms a bitvector to easily check them
        if isinstance(permissions, (int, long)):
            permissions = claripy.BVV(permissions, 3)

        # keep track of this region
        self._mapped_regions.append(MappedRegion(addr, length, permissions))

        if self.verbose: self.log("\t" + str(self._mapped_regions[-1]))

        # sort mapped regions 
        self._mapped_regions = sorted(self._mapped_regions, key=lambda x: x.addr)

    @profile
    def unmap_region(self, addr, length):

        if self.state.se.symbolic(addr):
            raise angr.SimMemoryError("cannot unmap region with a symbolic address")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.max_int(addr)

        self.timestamp += 1
        for a in range(addr, addr + length):
            self._concrete_memory[a] = MemoryItem(a, 0x0, self.timestamp, None)

        # remove from mapped regions
        for k in range(len(self._mapped_regions)):
            region = self._mapped_regions[k]
            if region.addr == addr:
                assert region.length == length
                del self._mapped_regions[k]
                break

        return

    @profile
    def permissions(self, addr):

        res_angr = None
        if self.angr_memory is not None:
            try:
                res_angr = self.angr_memory.permissions(addr)
            except Exception as e:
                res_angr = e

        # return permissions of the addr's region

        if self.state.se.symbolic(addr):
            assert False

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.eval(addr)

        for region in self._mapped_regions:
            if addr >= region.addr and addr <= region.addr + region.length:
                assert res_angr is None or self.state.se.eval_upto(res_angr, 10) == self.state.se.eval_upto(
                    region.permissions, 10)
                return region.permissions

        # Unmapped region: angr treats it as RW region
        assert res_angr is None or type(res_angr) in (angr.errors.SimMemoryError,)
        raise angr.errors.SimMemoryError("page does not exist at given address")

    @profile
    def check_sigsegv_and_refine(self, addr, min_addr, max_addr, write_access):

        if angr.options.STRICT_PAGE_ACCESS not in self.state.options:
            return

        # (min_addr, max_addr) is our range addr

        try:

            access_type = "write" if write_access else "read"

            if len(self._mapped_regions) == 0:
                raise angr.errors.SimSegfaultError(min_addr, "Invalid " + access_type + " access: [" + str(
                    hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

            last_covered_addr = min_addr - 1
            for region in self._mapped_regions:

                # region is after our range addr
                if max_addr < region.addr:
                    break

                # region is before our range addr
                if last_covered_addr + 1 > region.addr + region.length:
                    continue

                # there is one addr in our range that could be not covered by any region
                if last_covered_addr + 1 < region.addr:

                    # check with the solver: is there a solution for addr?
                    if self.state.se.satisfiable(
                            extra_constraints=(addr >= last_covered_addr + 1, addr < region.addr,)):
                        raise angr.errors.SimSegfaultError(last_covered_addr + 1,
                                                           "Invalid " + access_type + " access: [" + str(
                                                               hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                # last_covered_addr + 1 is inside this region
                # let's check for permissions

                upper_addr = min(region.addr + region.length, max_addr)
                if access_type == 'write':
                    if not region.is_writable() and self.state.se.satisfiable(
                            extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                        raise angr.errors.SimSegfaultError(last_covered_addr + 1,
                                                           "Invalid " + access_type + " access: [" + str(
                                                               hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                elif access_type == 'read':
                    if not region.is_readable() and self.state.se.satisfiable(
                            extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                        raise angr.errors.SimSegfaultError(last_covered_addr + 1,
                                                           "Invalid " + access_type + " access: [" + str(
                                                               hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                if max_addr > region.addr + region.length:
                    last_covered_addr = region.addr + region.length
                else:
                    last_covered_addr = max_addr

            # last region could not cover up to max_addr
            if last_covered_addr < max_addr:
                # we do not need to check with the solver since max_addr is already a valid solution for addr
                raise angr.errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + access_type + " access: [" + str(
                    hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

        except Exception as e:

            if type(e) in (angr.errors.SimSegfaultError,):
                raise e

            print full_stack()

    @profile
    def merge(self, others, merge_conditions, common_ancestor=None):

        assert common_ancestor is not None
        if type(common_ancestor) in (SimStateHistory,):
            ancestor_timestamp = common_ancestor.timestamps[0]
            ancestor_implicit_timestamp = common_ancestor.timestamps[1]
        else:
            ancestor_timestamp = common_ancestor.state.history.timestamps[0]
            ancestor_implicit_timestamp = common_ancestor.state.history.timestamps[1]

        if self.angr_memory is not None:
            self._compare_with_angr(op='pre_merge')
            others[0]._compare_with_angr(op='pre_merge_other')

        if self.angr_memory is not None:
            self.angr_memory.merge([others[0].angr_memory], merge_conditions, common_ancestor)

        # self.state.state_counter.log.append("[" + hex(self.state.regs.ip.args[0]) + "] " + "Merge")

        if self.verbose: self.log("Merging memories of " + str(len(others) + 1) + " states")
        assert len(merge_conditions) == 1 + len(others)
        assert len(others) == 1  # ToDo: add support for merging of multiple memories

        count = self._merge_concrete_memory(others[0], merge_conditions)
        count += self._merge_symbolic_memory(others[0], merge_conditions, ancestor_timestamp, ancestor_implicit_timestamp)

        self.timestamp = max(self.timestamp, others[0].timestamp) + 1
        self.implicit_timestamp = min(self.implicit_timestamp, others[0].implicit_timestamp)

        return count

    def post_merge(self):
        # print "POST MERGE"
        if self.angr_memory is not None:
            self._compare_with_angr(op='merge')

    @profile
    def _merge_concrete_memory(self, other, merge_conditions, verbose=False):

        # start_time = time.time()

        try:

            if self.verbose: self.log("Merging concrete addresses...")

            assert self._stack_range == other._stack_range

            # assert len(set(self._initializable._keys)) == 0
            # assert len(set(other._initializable._keys)) == 0

            missing_self = set(self._initializable._keys) - set(other._initializable._keys)
            for index in missing_self:
                self._load_init_data(index * 0x1000, 1)

            assert len(set(self._initializable._keys) - set(other._initializable._keys)) == 0

            missing_other = set(other._initializable._keys) - set(self._initializable._keys)
            for index in missing_other:
                other._load_init_data(index * 0x1000, 1)

            assert len(set(other._initializable._keys) - set(self._initializable._keys)) == 0

            count = 0

            # basic idea:
            # get all in-use addresses among both memories
            # for each address:
            #   - if it is in use in all memories and it has the same byte content then do nothing
            #   - otherwise map the address to an ite with all the possible contents + a bottom case

            page_indexes = set(self._concrete_memory._pages.keys())
            page_indexes |= set(other._concrete_memory._pages.keys())

            # assert len(page_indexes) == 0

            for page_index in page_indexes:

                # print "merging next page..."

                page_self = self._concrete_memory._pages[
                    page_index] if page_index in self._concrete_memory._pages else None
                page_other = other._concrete_memory._pages[
                    page_index] if page_index in other._concrete_memory._pages else None

                # shared page? if yes, do no touch it
                if id(page_self) == id(page_other):
                    continue

                offsets = set(page_self.keys()) if page_self is not None else set()
                offsets |= set(page_other.keys()) if page_other is not None else set()

                for offset in offsets:

                    v_self = page_self[offset] if page_self is not None and offset in page_self else None
                    v_other = page_other[offset] if page_other is not None and offset in page_other else None

                    if type(v_self) not in (list,) and type(v_other) not in (list,):

                        if v_self is not None and v_other is not None:
                            assert v_self.addr == v_other.addr
                            pass

                        same_value = v_self == v_other
                    else:
                        if type(v_self) != type(v_other):
                            same_value = False
                        elif len(v_self) != len(v_other):
                            same_value = False
                        else:
                            same_value = True
                            for k in range(len(v_self)):  # we only get equality when items are in the same order

                                sub_v_self = v_self[k]
                                sub_v_other = v_other[k]

                                assert type(sub_v_self) not in (list,)
                                assert type(sub_v_other) not in (list,)
                                assert sub_v_self.addr == sub_v_other.addr

                                if sub_v_self != sub_v_other:
                                    same_value = False
                                    break

                    # self has an initialized value that is missing in other
                    # we can keep as it is.
                    if v_other is None and v_self is not None and type(v_self) is not (
                            list,) and v_self.t == 0 and v_self.guard is None:
                        same_value = True

                    # Symmetric case. We need to insert in self.
                    if v_self is None and v_other is not None and type(v_other) is not (
                            list,) and v_other.t == 0 and v_other.guard is None:
                        self._concrete_memory[page_index * 0x1000 + offset] = v_other
                        same_value = True

                    if page_index * 0x1000 + offset == 134561792:
                        # pdb.set_trace()
                        pass

                    if not same_value:
                        count += 1
                        merged_value = self._copy_symbolic_items_and_apply_guard(v_self, merge_conditions[0]) \
                                       + self._copy_symbolic_items_and_apply_guard(v_other, merge_conditions[1])
                        assert len(merged_value) > 0
                        self._concrete_memory[page_index * 0x1000 + offset] = merged_value if len(merged_value) > 1 else \
                            merged_value[0]

            # end_time = time.time()
            # print "Merge concrete: " + str(end_time-start_time)

            return count

        except Exception as e:
            pdb.set_trace()

    def _copy_symbolic_items_and_apply_guard(self, L, guard):
        if L is None:
            return []
        if type(L) not in (list,):
            L = [L]
        LL = []
        for l in L:
            l = l.copy()
            l.guard = claripy.And(l.guard, guard) if l.guard is not None else guard
            LL.append(l)
        return LL

    @profile
    def _merge_symbolic_memory(self, other, merge_conditions, ancestor_timestamp, ancestor_timestamp_implicit, verbose=False):

        if self.verbose: self.log("Merging symbolic addresses...")

        # assert self.timestamp_implicit == 0
        # assert other.timestamp_implicit == 0
        # assert common_ancestor.timestamp_implicit == 0

        try:

            count = 0

            error = None

            try:
                P = self._symbolic_memory.search(0, sys.maxint)
                for p in P:
                    # assert p.data.t >= 0
                    if (p.data.t > 0 and p.data.t >= ancestor_timestamp) or (
                                    p.data.t < 0 and p.data.t <= ancestor_timestamp_implicit):
                        guard = claripy.And(p.data.guard, merge_conditions[0]) if p.data.guard is not None else \
                            merge_conditions[0]
                        i = MemoryItem(p.data.addr, p.data.obj, p.data.t, guard)
                        self._symbolic_memory.update_item(p, i)
                        count += 1
            except Exception as e:
                error = 1
                pdb.set_trace()

            try:
                P = other._symbolic_memory.search(0, sys.maxint)
                for p in P:
                    # assert p.data.t >= 0
                    if (p.data.t > 0 and p.data.t >= ancestor_timestamp) or (
                                    p.data.t < 0 and p.data.t <= ancestor_timestamp_implicit):
                        guard = claripy.And(p.data.guard, merge_conditions[1]) if p.data.guard is not None else \
                            merge_conditions[1]
                        i = MemoryItem(p.data.addr, p.data.obj, p.data.t, guard)
                        self._symbolic_memory.add(p.begin, p.end, i)
                        count += 1
            except Exception as e:
                error = 2
                pdb.set_trace()

            return count

        except Exception as e:
            pdb.set_trace()

    def _compare_with_angr(self, addrs=None, msg=None, op=None):

        try:

            if self.angr_memory is None or self.state is None:
                return

            # get in-use addresses in angr
            if addrs is None:

                addrs = set()
                for i, p in self.angr_memory.mem._pages.items():
                    addrs.update([k + i * 0x1000 for k in p.keys()])

                # Note: This check may fail. Indeed, we may have written
                #       an address even if this was not 
                #       addressable since we are not getting actual 
                #       solutions for an address. Even if the address is symbolic
                #       this could have forced loading of init data.
                addrs2 = set()
                for i, p in self._concrete_memory._pages.items():
                    addrs2.update([k + i * 0x1000 for k in p.keys()])

                if len(addrs2 - addrs) > 0:
                    # print "Our concrete memory has more addresses than angr's concrete memory..."
                    # import pdb
                    # pdb.set_trace()
                    pass

                addrs |= addrs2
                addrs = sorted(list(addrs))

            if self.verbose: print "\tChecking " + str(len(addrs)) + " addrs"

            # for addr check value
            for a in addrs:

                # if (a / 0x1000) not in self.angr_memory.mem._pages or (a % 0x1000) not in self.angr_memory.mem._pages[a / 0x1000]._storage:
                #    continue

                if self.verbose: print "\t\tComparing addr: " + hex(a)

                v1 = self.load(a, 1, internal=True)
                v2 = self.angr_memory.load(a, 1)
                comparison, s1, s2 = self._compare_bytes(v1, v2)

                if not comparison:
                    if self.verbose: print "\t\tMismatch at " + hex(a)
                    if self.verbose: print "\t\tValues from us:   " + str(s1)
                    if self.verbose: print "\t\tValues from angr: " + str(s2)

                    import pdb
                    pdb.set_trace()

                assert comparison

        except Exception as e:
            import pdb
            pdb.set_trace()

    def _compare_bytes(self, b1, b2):

        try:
            """
            print "Comparing: "
            print str(b1)
            print str(b2)
            """

            if id(b1) == id(b2):
                return True, b1, b2

            if b1.op == 'BVV' and b2.op == 'BVV':
                return b1.args[0] == b2.args[0], b1, b2

            if self.same(b1, b2):
                return True, b1, b2

            print "Comparing using models: "
            print "\t" + str(b1)
            print "\t" + str(b2)

            b1 = sorted(self.state.se.eval_upto(b1, 260))
            b2 = sorted(self.state.se.eval_upto(b2, 260))
            return b1 == b2, b1, b2

        except Exception as e:
            pdb.set_trace()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1):
        """
        Returns the address of bytes equal to 'what', starting from 'start'. Note that,  if you don't specify a default
        value, this search could cause the state to go unsat if no possible matching byte exists.

        :param addr:               The start address.
        :param what:                What to search for;
        :param max_search:          Search at most this many bytes.
        :param max_symbolic_bytes:  Search through at most this many symbolic bytes.
        :param default:             The default value, if what you're looking for wasn't found.

        :returns:                   An expression representing the address of the matching byte.
        """
        addr = self._raw_ast(addr)
        what = self._raw_ast(what)
        default = self._raw_ast(default)

        if isinstance(what, str):
            # Convert it to a BVV
            what = claripy.BVV(what, len(what) * self.state.arch.byte_width)

        r,c,m = self._find(addr, what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default,
                           step=step)

        if angr.options.AST_DEPS in self.state.options and self.category == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        return r,c,m

    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1):
        if max_search is None:
            max_search = angr.state_plugins.SimSymbolicMemory.DEFAULT_MAX_SEARCH

        if isinstance(start, (int, long)):
            start = self.state.se.BVV(start, self.state.arch.bits)

        constraints = [ ]
        remaining_symbolic = max_symbolic_bytes
        seek_size = len(what)//self.state.arch.byte_width
        symbolic_what = self.state.se.symbolic(what)

        chunk_start = 0
        chunk_size = max(0x100, seek_size + 0x80)
        chunk = self.load(start, chunk_size, endness="Iend_BE")

        cases = [ ]
        match_indices = [ ]
        offsets_matched = [ ] # Only used in static mode

        import itertools
        for i in itertools.count(step=step):
            if i > max_search - seek_size:
                break
            if remaining_symbolic is not None and remaining_symbolic == 0:
                break
            if i - chunk_start > chunk_size - seek_size:
                chunk_start += chunk_size - seek_size + 1
                chunk = self.load(start+chunk_start, chunk_size,
                        endness="Iend_BE", ret_on_segv=True)

            chunk_off = i-chunk_start
            b = chunk[chunk_size*self.state.arch.byte_width - chunk_off*self.state.arch.byte_width - 1 : chunk_size*self.state.arch.byte_width - chunk_off*self.state.arch.byte_width - seek_size*self.state.arch.byte_width]
            cases.append([b == what, start + i])
            match_indices.append(i)

            if self.state.mode == 'static':
                si = b._model_vsa
                what_si = what._model_vsa

                if isinstance(si, claripy.vsa.StridedInterval):
                    if not si.intersection(what_si).is_empty:
                        offsets_matched.append(start + i)

                    if si.identical(what_si):
                        break

                    if si.cardinality != 1:
                        if remaining_symbolic is not None:
                            remaining_symbolic -= 1
                else:
                    # Comparison with other types (like IfProxy or ValueSet) is not supported
                    if remaining_symbolic is not None:
                        remaining_symbolic -= 1

            else:
                # other modes (e.g. symbolic mode)
                if not b.symbolic and not symbolic_what and self.state.se.eval(b) == self.state.se.eval(what):
                    break
                else:
                    if b.symbolic and remaining_symbolic is not None:
                        remaining_symbolic -= 1

        if self.state.mode == 'static':
            r = self.state.se.ESI(self.state.arch.bits)
            for off in offsets_matched:
                r = r.union(off)

            constraints = [ ]
            return r, constraints, match_indices

        else:
            if default is None:
                default = 0
                constraints += [ self.state.se.Or(*[ c for c,_ in cases]) ]

            #l.debug("running ite_cases %s, %s", cases, default)
            r = self.state.se.ite_cases(cases, default)
            return r, constraints, match_indices

    def __contains__(self, addr):

        if isinstance(addr, (int, long)):
            addr = addr
        elif self.state.se.symbolic(addr):
            log.warning("Currently unable to do SimMemory.__contains__ on symbolic variables.")
            return False
        else:
            addr = self.state.se.eval(addr)

        # concrete address
        if type(addr) in (int, long):
            min_addr = addr
            max_addr = addr

        # symbolic addr
        else:
            min_addr = self.state.se.min_int(addr)
            max_addr = self.state.se.max_int(addr)
            if min_addr == max_addr:
                addr = min_addr

        # check permissions
        self.check_sigsegv_and_refine(addr, min_addr, max_addr, False)

        # check if binary data should be loaded into address space
        self._load_init_data(min_addr, (max_addr - min_addr) + 1)

        P = self._concrete_memory.find(min_addr, max_addr, True)

        P += [x.data for x in self._symbolic_memory.search(min_addr, max_addr + 1)]
        P = sorted(P, key=lambda x: (x.t, (x.addr if type(x.addr) in (int, long) else 0)))

        return len(P) > 0