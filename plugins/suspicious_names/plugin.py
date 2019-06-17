# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO! Plugin
# Find suspicious names

import os
import logging
import logging.handlers


class Plugin:
    """
    """

    def __init__(self, swf=None, ml=None, names=[]):
        self.swf = swf
        self.user_names = names

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
        self.ml.info("Looking for suspicious names...")

        return self._find_suspicious_names()

    def _find_suspicious_names(self):
        """Searches the constant pool(s) for suspicious names

        User-defined names can be added as well
        """

        suspicious_names = []

        funky_strings = ['overflow', 'spray', 'shell', 'crypt', 'virt', 'protect',
                         'vuln', 'li32', 'si32', 'xor', 'encode', 'decode',
                         'sleep', 'key']
        funky_strings += self.user_names

        for s in self.swf.strings:
            for funky in funky_strings:
                if funky in s.lower():
                    suspicious_names.append(s)

        return suspicious_names
