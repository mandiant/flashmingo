# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# This finds suspicious constants in the constant pool(s)

import os
import logging
import logging.handlers


class Plugin:
    """
    All plugins work on a SWFObject passed 
    as an argument
    """

    def __init__(self, swf=None, ml=None, constants=[]):
        self.swf = swf
        self.user_constants = constants

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
        self.ml.info("Looking for suspicious constants...")

        return self._find_suspicious_constants()

    def _find_suspicious_constants(self):
        """Find suspicious constants

        Some things are pretty fishy, like for example
        `MZ` or `PE` magic numbers
        We search for this in the constant pool
        """

        suspicious_constants = []

        funky_constants = [0x4550, 0x5a4d, 0x905a4d, 0x90905a4d]
        funky_constants += self.user_constants

        for c in self.swf.constants:
            if c in funky_constants:
                suspicious_constants.append(c)

        return suspicious_constants
