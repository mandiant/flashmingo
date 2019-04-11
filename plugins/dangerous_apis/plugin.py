# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# This plugin searches for APIs known to be abused
# for example, direct memory accesses

import os
import logging
import logging.handlers


class Plugin:
    """
    All plugins work on a SWFObject passed 
    as an argument
    """
    def __init__(self, swf=None, ml=None, apis=[]):
        self.swf = swf
        self.user_apis = apis

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
        self.ml.info("Checking for suspicious APIs...")

        return self._find_suspicious_apis()

    def _find_suspicious_apis(self):
        """ Crazyness """
        funky_instructions = ['si32', 'li32']
        funky_instructions += self.user_apis

        suspicious_apis = set([])

        instances = self.swf.instance_info

        for class_name, instance_info in instances.iteritems():
            methods = instance_info['methods']

            for method_name in methods:
                ins_list = self.swf.disassemble_method(method_name)

                for ins in ins_list:
                    for funky_ins in funky_instructions:
                        if funky_ins in ins:
                            suspicious_apis.add((class_name, method_name))

        return suspicious_apis
