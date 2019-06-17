# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# Get all binary data embedded in the SWF

import os
import logging
import logging.handlers


class Plugin:
    """
    All plugins work on a SWFObject passed 
    as an argument
    """
    def __init__(self, swf=None, ml=None, pattern=None):
        self.swf = swf
        self.pattern = pattern

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
        """Get embedded binary data information

        If the plugin is called with a `pattern` parameter it will 
        search for it in all the embedded binary data tags.
        Called without this parameter it just returns all data.
        """

        if not self.pattern:
            self.ml.info("No pattern specified. Returning all embedded data")
            return self.swf.binary_data
        else:
            self.ml.info("Searching the embedded binary data...")
            return self._inspect_binary_data()

    def _inspect_binary_data(self):
        """Looks for a pattern within the embedded binary data

        Examples of patterns to look for are malware signatures, 
        file magic numbers, etc.
        """

        found_pattern = {}

        for class_name, data in self.swf.binary_data.items():
            self.ml.debug("Inspecting {}'s binary data".format(class_name))

            offset = data.find(self.pattern)

            if offset >= 0:
                found_pattern[class_name] = offset

        return found_pattern
