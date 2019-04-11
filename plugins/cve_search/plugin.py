# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# This is a template for easy development

import os
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
        """Search for known CVEs"""
        self.ml.info("Searching for known CVEs footprints...")

        possible_cves = self._search_for_cves()

        return possible_cves
    
    def _search_for_cves(self):
        """This is a very quick & dirty implementation
        Heuristics can be refined further... a lot

        For now, it will just look for substrings in 
        the disassembled code
        """

        # This list is from dzzie's pdfstreamduper
        # https://github.com/dzzie/pdfstreamdumper
        cve_hints = {
            "CVE-2015-5122": [".opaqueBackground"],
            "CVE-2015-3113": ["play", "info", "code", "video", "attachNetStream"],
            "CVE-2015-0556": ["copyPixelsToByteArray"],
            "CVE-2015-0313": ["createMessageChannel", "createWorker"],
            "CVE-2015-0310 or CVE-2013-0634": ["new RegExp"],
            "CVE-2015-0311": ["domainMemory", "uncompress"],
            "CVE-2014-9163": ["parseFloat"],
            "CVE-2014-0515 (if in while loop)": ["byteCode", "Shader"],
            "CVE-2014-0502": ["setSharedProperty", "createWorker", ".start", "SharedObject"],
            "CVE-2014-0497": ["writeUTFBytes", "domainMemory"],
            "CVE-2012-0779": ["defaultObjectEncoding", "AMF0", "NetConnection"],
            "CVE-2012-0754": ["NetStream", "NetConnection", "attachNetStream", "play"],
            "CVE-2012-5054": ["Matrix3D"],
            "CVE-2012-0779": ["Responder", "NetConnection", "AMF0"],
            "CVE-2012-1535": ["FontDescription", "FontLookup"],
            "CVE-2011-0609": ["MovieClip", "TimelineMax", "TweenMax"],
            "CVE-2011-2110": ["Number(_args["],
            "Loads embedded flash object": ["loadbytes"],
        }

        possible_cves = []

        if not self.swf.decompiled_methods:
            self.ml.error("Run decompiler plugin first!")
            return

        for cve, hints in cve_hints.iteritems():
            for abc_name, decompiled_text in self.swf.decompiled_methods.iteritems():
                for mo_idx, method_dec in decompiled_text.iteritems():
                    # Keep track of the substrings found
                    for hint in hints[:]:  # deepcopy
                        if hint in method_dec:
                            hints.remove(hint)

                            if not hints:
                                # Found all hints!
                                possible_cves.append(cve)

        return possible_cves
