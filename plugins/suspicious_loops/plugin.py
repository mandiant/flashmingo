# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO! Plugin
# Finds loops containing suspicious constructs

import os
import logging
import logging.handlers


class Plugin:
    """
    All plugins work on a SWFObject passed 
    as an argument
    """

    def __init__(self, swf=None, ml=None, ins=[]):
        self.swf = swf
        self.user_ins_list = ins

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
        self.ml.info("Looking for suspicious loops...")

        return self._find_suspicious_loops()

    def _find_suspicious_loops(self):
        """Finds suspicious constructs within loops

        This heuristic can point out to encryption/decryption 
        routines (ex. loops containing `bitxor` instructions)
        An user defined list of instructions can be used as well
        """

        suspicious_methods = []

        suspicious_ins = ['bitxor', 'bitand', 'bitor']
        suspicious_ins += self.user_ins_list

        method_names = self.swf.get_all_method_names()

        for method_name in method_names:
            loop_ins = self.swf.find_simple_loops(method_name)

            for ins in loop_ins:
                if ins in suspicious_ins:
                    # NOTE: this could be refined with some kind of
                    # metric. For now we mark the method as soon
                    # as we find one of these instructions
                    suspicious_methods.append(method_name)
                    break

        return suspicious_methods
