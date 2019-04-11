# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# SWF object file


import swiffas
from swiffas import swftags

from collections import defaultdict
import subprocess


class MethodObj:
    """This contains all information about a method

    This bare-bones class is used to get something 
    resembling a C-struct in Python
    """

    def __init__(self, abc=None, idx=0, name='', bytecode=None,
                 instructions=None, local_count=0, trait_count=0,
                 param_count=0, return_type=''):
        self.abc = abc

        # The index into the "methods" array 
        # of *this* ABC 
        self.idx = idx

        # The string within *this* ABC's constant pool
        self.name = name

        self.param_count = param_count
        self.return_type = return_type

        # From the MethodBodyInfo object
        self.bytecode = bytecode
        self.instructions = instructions
        self.local_count = local_count
        self.trait_count = trait_count

        # From the FFDEC plugin
        self.source = {}


class SWFObject:
    """Represents a SWF file structure and contents

    FLASHMINGO acts on instances of this class to 
    analyze the samples.
    """

    def __init__(self, filename, ml=None):
        if not ml:
            print 'No logging facility'
            raise ValueError

        if not filename:
            raise ValueError

        self.ml = ml
        self.filename = filename

        # Initialize all components
        self.tags = self.get_all_tags()

        # Actionscript ByteCode (ABC) tags 
        # are very important for obvious reasons
        self.abcs = self.get_all_abcs()
        self.abc_list = self.abcs.values()

        self.instance_info = self.get_all_instances_info()
        self.namespaces = self.get_namespaces()
        self.multinames = self.get_multinames()
        self.method_objects = self.get_all_method_objects()
        self.strings = self.get_all_strings()
        self.constants = self.get_all_constants()
        self.binary_data = self.get_all_binary_data()

        self.decompiled_methods = {}

    def get_all_tags(self):
        """Opens a SWF file and parses its tags

        Returns:
            A list of Tag objects
        """

        p = swiffas.SWFParser()
        with open(self.filename, 'rb') as f:
            p.parse(f)

        tags = [x for x in p.tags]

        return tags

    def get_all_abcs(self):
        """Reads all ABC tags for a given SWF

        Returns:
            A dictionary of ABCFile objects, one for each DoABC tag found
        """

        abc_d = {}

        for tag in self.tags:
            if isinstance(tag, swftags.DoABC):
                abc = swiffas.ABCFile(tag.bytecode, 0, len(tag.bytecode))
                name = tag.name

                self.ml.debug("Tag {} has {} methods".format(name, len(abc.methods)))

                abc_d[name] = abc

        return abc_d

    def get_all_instances_info(self):
        """Gets all class instances and their traits

        Traits are methods, vars, etc.
        The information from this method provides a high 
        level overview of the methods and variables in 
        the entire codebase!

        NOTE: This will miss unused code (no instance)
        """

        instances = {}

        for abc in self.abc_list:
            for ii in abc.instances:
                mni = abc.constant_pool.multinames[ii.multiname_idx - 1]
                instance_name = abc.constant_pool.strings[mni.name_idx - 1].value

                bci = abc.constant_pool.multinames[ii.super_multiname_idx - 1]
                base_name = abc.constant_pool.strings[bci.name_idx - 1].value

                instances[instance_name] = {
                    'base_class': base_name,
                    'constructor': '',
                    'globals': [],
                    'constants': [],
                    'methods': []
                }

                # Constructor
                cctor = abc.methods[ii.iinit]  # MethodInfo
                cctor_name = abc.constant_pool.strings[cctor.name - 1].value

                # NOTE: this produces strange results with some samples
                # probably several classes sharing a dummy constructor...
                instances[instance_name]['constructor'] = cctor_name

                # Traits
                # NOTE: not all InstanceInfo has Traits
                if getattr(ii, 'trait', None):
                    for ti in ii.trait:

                        if ti.kind == ti.Class:
                            pass

                        elif ti.kind == ti.Function:
                            pass

                        elif ti.kind in (ti.Function, ti.Method, ti.Getter, ti.Setter):
                            mi = abc.methods[ti.method_idx - 1]
                            name = abc.constant_pool.strings[mi.name - 1].value
                            instances[instance_name]['methods'].append(name)

                        elif ti.kind in (ti.Const, ti.Slot):
                            # Trait Slot correlates roughly with global (instance) variables,
                            # Trait Const with global (instance) constants
                            if getattr(ti, 'multiname_idx', None):
                                glob = self.lookup_multiname(abc=abc, idx=ti.multiname_idx)
                                g_type = self.lookup_multiname(abc=abc, idx=ti.type_name)

                            #
                            # See "AVM2 Overview" (p.26) for an explanation of these constants
                            # NOTE: Only numerical values for now
                            if getattr(ti, 'vkind', None):
                                if ti.vkind == 4:
                                    # uint constant pool
                                    value = abc.constant_pool.uints[ti.vindex - 1]
                                elif ti.vkind == 3:
                                    # int constant pool
                                    value = abc.constant_pool.ints[ti.vindex - 1]
                                else:
                                    value = 'unk'

                                instances[instance_name]['globals'].append((glob, g_type, value))

        return instances

    def get_namespaces(self):
        """Retrieves all namespace information

        Args:
            None

        Returns:
            A set of tuples: [(kind, name), ...] 
        """
        namespaces = set([])

        # This comes from the AVM2 specification document
        ns_kind = {0x08: 'CONSTANT_Namespace',
                   0x16: 'CONSTANT_PackageNamespace',  # Package
                   0x17: 'CONSTANT_PackageInternalNs',  # Package
                   0x18: 'CONSTANT_ProtectedNamespace',
                   0x19: 'CONSTANT_ExplicitNamespace',
                   0x1A: 'CONSTANT_StaticProtectedNs',
                   0x05: 'CONSTANT_PrivateNs'
                   }

        for abc in self.abc_list:
            for ns in abc.constant_pool.namespaces:
                n = ns.name
                # The "name" is an index!
                if n != 1:
                    ns_name = abc.constant_pool.strings[n - 1].value
                    if ns_name:
                        namespaces.add((ns_kind[ns.kind], ns_name))

        return namespaces

    def get_multinames(self):
        """Retrieves multinames information 

        Returns:
            Dictionary of sets: {namespace: {multiname, ...}, ...}
        """

        multiname_d = defaultdict(set)

        # This comes from the AVM2 specification document
        mn_kind = {0x07: 'QName',
                   0x0D: 'QNameA',
                   0x0F: 'RTQName',
                   0x10: 'RTQNameA',
                   0x11: 'RTQNameL',
                   0x12: 'RTQNameLA',
                   0x09: 'Multiname',
                   0x0E: 'MultinameA',
                   0x1B: 'MultinameL',
                   0x1C: 'MultinameLA',
                   }

        for abc in self.abc_list:
            for mni in abc.constant_pool.multinames:
                mn_ns = None
                mn_name = None

                # NOTE: Not all Multinames have these attributes
                if getattr(mni, 'name_idx', None):
                    idx = mni.name_idx
                    if idx != 0:
                        mn_name = abc.constant_pool.strings[idx - 1].value
                else:
                    mn_name = 'unk NAME'

                if getattr(mni, 'namespace_idx', None):
                    ns_idx = mni.namespace_idx
                    if ns_idx != 0:
                        mni_ = abc.constant_pool.namespaces[ns_idx - 1]
                        mn_ns = abc.constant_pool.strings[mni_.name - 1].value
                else:
                    mn_ns = 'unk NS'

                for instance_name in self.instance_info.keys():
                    if mn_ns in instance_name:
                        # This may seem convoluted but it allows to match
                        # XXX and FilePrivateNS:XXX
                        multiname_d[mn_ns].add(mn_name)

        return multiname_d

    def get_all_method_objects(self, anon=True):
        """
        Populates a list of method objects
        Method indexes are important because it is the way they
        are referenced by the decompiler service (FFDEC)

        NOTE: iterating over the method bodies leaves out, of course, 
        methods without a body. These are uninteresting anyway.
        """
        method_objects = []

        for abc in self.abc_list:
            for method_body_info in abc.method_bodies:

                method_info = abc.methods[method_body_info.method]
                name = method_info.name

                if name != 0:
                    method_name = abc.constant_pool.strings[name - 1].value
                else:
                    if not anon:
                        continue

                    # method_info.name == 0 represents an anonymous method
                    # These are just referenced as ordinals
                    method_name = "anon_method_{}".format(method_body_info.method)

                bytecode = method_body_info.code

                # iter_bytecode() returns a generator that can 
                # get exhausted. Coerce it to a list.
                instructions = list(method_body_info.iter_bytecode())
                local_count = method_body_info.local_count
                trait_count = method_body_info.trait_count
                param_count = method_info.param_count

                # The return type is tricky. An index to the Multinames
                rt = method_info.return_type

                if rt == 0:
                    return_type = '*'
                else:
                    mn = abc.constant_pool.multinames[rt - 1]
                    return_type = abc.constant_pool.strings[mn.name_idx - 1].value

                m = MethodObj(abc=abc, idx=method_body_info.method, name=method_name, bytecode=bytecode,
                              instructions=instructions, local_count=local_count, trait_count=trait_count,
                              param_count=param_count, return_type=return_type)

                method_objects.append(m)

        return method_objects

    def get_all_strings(self):
        """
        Retrieves a list of ALL strings in
        all constant pools from all ABCs
        Get it? ALL of them! :)
        """
        all_strings = set([])

        for abc in self.abc_list:
            for s in abc.constant_pool.strings:
                all_strings.add(s.value)

        return all_strings

    def get_all_constants(self):
        """
        This queries the Constant Pool
        """
        all_constants = []

        for abc in self.abc_list:
            all_constants += abc.constant_pool.uints
            all_constants += abc.constant_pool.ints

        return all_constants

    def get_all_binary_data(self):
        """
        Returns a dictionary of
        embedded binary data indexed by class name
        """
        binary_tags = []
        symbol_tag = None
        symbols = dict()
        binary_data = dict()

        # Find all DefineBinaryData tags and the symbol one
        # There is only *one* symbol tag
        for tag in self.tags:
            if isinstance(tag, swftags.DefineBinaryData):
                binary_tags.append(tag)
            elif isinstance(tag, swftags.SymbolClass):
                symbol_tag = tag

        # Populate the symbols dict, indexed by character_id
        # Ex. {1 : "DescTop", ...}
        for sym in symbol_tag.symbols:
            symbols[sym.character_id] = sym.name

        # Populate the binary data dict
        for bin_tag in binary_tags:
            class_name = symbols[bin_tag.character_id]
            binary_data[class_name] = bin_tag.data

        return binary_data

    def decompile_method(self, method_name):
        """Gets a method's decompiled text

        Given a MethodObject, it returns its decompiled form 
        This is not intended to be called directly but used 
        internally instead

        Args:
            method_name: the MethodObject name

        Returns:
            The decompiled text form of this method
        """

        if not self.decompiled_methods:
            return "no decompilation available"

        mo = self.get_method_obj_by_name(method_name)
        if not mo:
            return "no decompilation available"

        if mo.idx == 0:
            return "no decompilation available"

        # Get ABC's name
        abc_name = ''

        for name, abc in self.abcs.iteritems():
            if mo.abc == abc:
                abc_name = name
                break

        if not abc_name:
            # Can't find ABC's name
            return "no decompilation"

        self.ml.debug("ABC name: {} mo.idx: {}".format(abc_name, mo.idx))

        try:
            source = self.decompiled_methods[abc_name][str(mo.idx)]
        except KeyError as e:
            source = "no decompilation available"

        return source

    def get_function_calls(self, method_name):
        """Get all function calls within a method

        Args:
            method_name: the method's name

        Returns:
            A set containing names of all called functions
        """

        avm2calls = (
            'callpropvoid',
            'callproperty',
            'callproplex',
            'callmethod',
            'callstatic',
            'callsuper',
            'callsupervoid'
        )

        calls = set([])

        mo = self.get_method_obj_by_name(method_name)
        if not mo:
            return []

        for ins in mo.instructions:
            if ins._name in avm2calls:
                qname_idx = ins.__dict__['index']
                arg_cnt = ins.__dict__['arg_count']
                func_name = self.lookup_multiname(abc=mo.abc, idx=qname_idx)

                self.ml.debug("- {} ({} args)".format(func_name, arg_cnt))
                calls.add(func_name)

        return calls

    # ---------------------------------------------------------------
    # Auxiliary and convenience methods
    # ---------------------------------------------------------------
    def string_from_index(self, abc=None, idx=0):
        if not idx or idx == 0 or not abc:
            raise ValueError

        s = abc.constant_pool.strings[idx - 1].value
        return s

    def multiname_from_index(self, abc=None, idx=0):
        if not abc:
            raise ValueError

        if idx == 0:
            return '*'

        i = abc.constant_pool.multinames[idx - 1].name_idx
        s = abc.constant_pool.strings[i - 1].value
        return s

    def lookup(self, from_index=None, abc=None, idx=0):
        """It queries the constant pool(s)

        Used dependency injection to avoid code repetition
        """
        s = None

        if not abc:
            self.ml.warning("Best effort search. May produce inaccurate results")

            for abc in self.abc_list:
                try:
                    s = from_index(abc, idx)
                    break
                except IndexError:
                    # I will go to anti-pattern hell for this
                    continue
        else:
            s = from_index(abc, idx)

        return s

    def lookup_multiname(self, abc=None, idx=0):
        """ This is a convenience method """
        return self.lookup(from_index=self.multiname_from_index, abc=abc, idx=idx)

    def lookup_string(self, abc=None, idx=0):
        """ This is a convenience method """
        return self.lookup(from_index=self.string_from_index, abc=abc, idx=idx)

    def get_all_method_names(self, anon=True):
        """Retrieves all method names

        This may seem redundant. Why not just use self.method_objects?
        This gives us the flexibility to run this again with a different 
        value of "anon"
        """
        m_objs = self.get_all_method_objects(anon)

        return [m.name for m in m_objs]

    def get_instance_for_method(self, method_name):
        """Finds to which instance a method belongs to

        It is so unnerving to know only a method name and need 
        to start navigating all instances to find which one 
        this belongs to

        Args:
            method_name: the method's name

        Returns:
            The instance name associated with this method or None
        """

        for instance_name, ii in self.instance_info.iteritems():
            if method_name in ii['methods']:
                return instance_name

        return None

    def get_method_obj_by_name(self, name):
        """
        NOTE: this poses a problem with unnamed methods
        """
        for mo in self.method_objects:
            if mo.name == name:
                return mo

        self.ml.warning("Method {} not found".format(name))

        return None

    def disassemble_method(self, method_name):
        """Dump the bytecode instructions in a method

        Args:
            method_name: method's name

        Returns:
            A list of strings, the AS3 bytecode instructions
        """

        instructions = []

        mo = self.get_method_obj_by_name(method_name)
        if not mo:
            return []

        # Found the method body corresponding to that name!
        # Let's display a nice representation of its bytecode
        for ins in mo.instructions:
            if not ins._fields:
                instructions.append("{}".format(ins._name))
            else:
                pretty_fields = map(lambda f: "{}: {}".format(f, ins.__dict__[f]), ins._fields)
                instructions.append("{} ({})".format(ins._name, pretty_fields))

        return instructions

    def debug_instruction(self, ins):
        """For debugging only

        This is a development helper to get debug information 
        regarding an ActionScript ByteCode instruction.
        """
        print ins._name

        for x in ins._fields:
            print ' -', x, ins.__dict__[x]

    def find_simple_loops(self, method_name):
        """Finds simple loops within a method

        The most interesting things happen within loops
        (encryption, decoding, ByteArray manipulation)
        This primitive yields the AVM2 instructions contained in 
        single loops and can be the basis for some heuristics.
        For example, is there bitxor instructions, etc.

        This is a bit hacky but does the trick for now.

        Following instruction's pattern translates to a loop:

        jump off_A
        off_B: label
        [...]
        off_A: some instructions implementing the comparison
        [...]
        iflt off_B  // or any other ifXXX instruction

        Args:
            method_name: a method's name

        Returns:
            A list of instructions within a simple loop
        """

        loop_ins = []

        mo = self.get_method_obj_by_name(method_name)
        if not mo:
            self.ml.error("Could not find method {}".format(method_name))
            return None

        f_loop = False

        last_ins = mo.instructions[0]
        last_offset = 0
        jump_offset = 0
        offset = last_ins._size + 1  # One byte is the opcode

        for curr_ins in mo.instructions[1:]:
            # Flag whether we are within a loop
            if last_ins._name == 'jump' and curr_ins._name == 'label':
                f_loop = True
                jump_offset = last_offset

            if curr_ins._name.startswith('if'):
                # and offset is correct
                delta = curr_ins.__dict__['offset']
                # Remember that delta is negative :)
                if offset + delta == jump_offset:
                    f_loop = False

            #
            # Get the instructions within the loop
            if f_loop:
                loop_ins.append(curr_ins._name)

            last_ins = curr_ins
            last_offset = offset
            offset += curr_ins._size + 1

        return loop_ins
