# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO! examples
# A collection of simple examples to help you kickstart development


def test_multinames(swf):
    print("Getting MultiNames information...")

    for mn_ns, mn_items in swf.multinames.items():
        print("MultiNAME ({})".format(mn_ns))
        print(", ".join(mn_items))
        print()


def test_method(swf, method_name):
    """Extracts information from a method

    Given a method name, this test mines all available 
    information from the corresponding SWF
    """

    mo = swf.get_method_obj_by_name(method_name)
    if not mo:
        print("[!] Could not find method {}".format(method_name))
        return

    print("Method information for {}".format(method_name))
    print()
    print("{} ({} params, {} locals): {} [idx: {}]".format(
        mo.name, mo.param_count, mo.local_count, mo.return_type, mo.idx))

    print("Decompilation")
    print()
    print(swf.decompile_method(method_name))

    print("Function calls")
    print()
    for call in swf.get_function_calls(method_name):
        print(call)

    print("Raw Disassembly")
    print()
    for ins in swf.disassemble_method(method_name):
        print(ins)


def test_instances(swf, instance_name=''):
    """Prints an instance's information

    If no instance's name is given, print all.
    Instances can be thought as the SWF scripts
    
    Args:
        instance_name: name of an instance

    Returns: 
        None
    """

    print("Getting instance information...")

    for name, ii in swf.instance_info.items():
        if instance_name and name != instance_name:
            continue

        print("instance ({})".format(name))
        print(ii)
        print()


def test_namespaces(swf):
    """Simple wrapper to display Namespaces data
    """
    print("Getting Namespaces information...")

    for kind, name in swf.namespaces:
        print(kind, name)


def test_debug_method(swf, method_name):
    """Get debug information for all instructions in a method

    This is useful during development mainly
    """
    print("Debug disassembly")
    mo = swf.get_method_obj_by_name(method_name)

    offset = 0
    for ins in mo.instructions:
        print("[{} ({})]".format(offset, ins._size + 1))
        swf.debug_instruction(ins)
        offset += ins._size + 1
