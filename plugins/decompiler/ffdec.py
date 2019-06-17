# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# Interact with the JPEXS decompiler library

import os
import sys

sys.path.append("ffdec_lib/ffdec_lib.jar")

import json

import ffdec_lib
import com.jpexs.decompiler.flash as f
import com.jpexs.decompiler.flash.abc.avm2.deobfuscation.DeobfuscationLevel as DeobfuscationLevel

from com.jpexs.decompiler.flash.abc import RenameType




def main():
    swf = None
    decompilation_d = {}

    if len(sys.argv) < 2:
        print("Usage: {} <SWFFILE>".format(sys.argv[0]))
        sys.exit(1)
    else:
        SWFFILE = sys.argv[1]

    print("[*] Reading file: {}...".format(SWFFILE))

    try:
        with open(SWFFILE, "rb") as fp:
            swf = f.SWF(fp, False)
    except Exception as e:
        print("[x] FFDEC: Failed to process the sample file: {}".format(e))
        return

    # -------------------------------------------
    # SWF-level preprocessing
    # -------------------------------------------
    level = DeobfuscationLevel.getByLevel(1)
    swf.deobfuscate(level)

    # Get rid of crazy invalid identifiers
    swf.deobfuscateIdentifiers(RenameType.RANDOMWORD)
    swf.assignClassesToSymbols()

    # General information
    print("[*] The entry point is {}".format(swf.documentClass))

    # This is roughly equivalent to instance names in SWIFFAS
    as3packs = swf.getAS3Packs()
    for as3pack in as3packs:
        print("- {}".format(as3pack.nameWithNamespaceSuffix))

    for tag in swf.abcList:
        try:
            print("TAG: {}".format(tag))
            decompilation_d[tag.name] = {}

            # AS3 ByteCode!
            abc = tag.getABC()

            # NOTE: Not sure whether this has some effect
            # Worst case scenario this is idem-potent
            abc.removeDeadCode()

            bodies = abc.bodies

            for body in bodies:
                # This is the AVM2 ByteCode for this method's body
                # It is just an array of bytes, as expected :)
                avm2_bytecode = body.codeBytes

                # This however is the string repr of the disassembly
                # with mnemonics applied
                avm2_code = body.code

                # Unsurprisingly this produces the method's body 
                # decompilation :D
                index = body.method_info

                decompilation_d[tag.name][index] = body.toSource()

        except Exception as e:
            print("[x] Failed to process tag {}: {}".format(tag, e))

    print("[*] Dumping decompiled methods to a JSON file...")

    with open('decompilation.json', 'w') as fp:
        fp.write(json.dumps(decompilation_d))

    print("[*] Done.")

    # Sometimes this hangs in there
    # and needs some help exiting :)
    sys.exit(0)



if __name__ == '__main__':
    main()
