# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# This is a preliminary version of a module to interact with FFDEC decompiler
# It spawns a subprocess calling a Jython script to interact with the Java library

import os
import json
import subprocess

import logging
import logging.handlers


class Plugin:
    """
    All plugins work on a SWFObject passed 
    as an argument
    """

    def __init__(self, swf=None, ml=None):
        self.swf = swf

        if not ml:
            self.ml = self._init_logging()
        else:
            self.ml = ml

        self.ml.info('Plugin started')

    def _init_logging(self):
        """
        Plugins will inherit from this class to have 
        a consistent logging scheme
        """
        logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
                            level=logging.DEBUG)
        fmt = logging.Formatter('%(asctime)-12s [%(levelname)s] %(message)s')

        log_dir = os.path.dirname(os.path.realpath(__file__))
        log_filename = os.path.join(log_dir, 'plugin.log')

        handler = logging.handlers.RotatingFileHandler(
            log_filename,
            maxBytes=5 * 1024 * 1024,
            backupCount=5)

        handler.setLevel(logging.DEBUG)
        handler.setFormatter(fmt)

        ml = logging.getLogger('main')
        ml.addHandler(handler)

        return ml

    def run(self):
        self.ml.info("Decompiling the entire SWF...")

        return self._decompile_swf()

    # ------------------------------------------
    # Decompilation by FFDEC lib
    # ------------------------------------------
    def _decompile_swf(self):
        """Let's keep this simple for now
        The decompilation is saved to a file in JSON format
        """

        decompiled_methods = {}
        plugin_loc = os.path.dirname(os.path.realpath(__file__))

        # This is blocking. We want this.
        try:
            subprocess.call([
                # For Windows systems:
                # 'C:\\jython2.7.0\\bin\\jython.exe',
                'jython',
                'ffdec.py',
                self.swf.filename
            ],
                cwd=plugin_loc)
        except Exception as e:
            print("[x] Decompilation subprocess failed!")
            return

        input_file = os.path.join(plugin_loc, 'decompilation.json')

        try:
            with open(input_file, 'r') as fj:
                decompiled_methods = json.loads(fj.read())
        except IOError as e:
            print("[x] Failed to read decompilation file: {}".format(e))

        return decompiled_methods
