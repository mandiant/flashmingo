# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# The tool for all your Flash analysis needs... with a funny name!

import sys
import logging
import logging.handlers
import warnings
import cmd2

from flashmingo.resources import flashmingo_banner, flashcmd_goodbye
from flashmingo.Flashmingo import Flashmingo
from flashmingo.SWFObject import SWFObject


class FlashmingoCmd(cmd2.Cmd):
    """FLASHMINGO Cmd2 App"""

    def __init__(self):
        cmd2.Cmd.__init__(self)

        self.prompt = "[flashmingo] > "
        # Logging
        logger = self._init_logging()
        if not logger:
            sys.exit(1)

        self.logger = logger
        self.logger.propagate = False
        self.fm = Flashmingo(ml=logger)
        self.swf = None
        self.has_decompilation = False
        self.plugins_done = set([])

    def preloop(self):
        """ Banner """

        print flashmingo_banner

    def postloop(self):
        """ Exit message """

        print flashcmd_goodbye

    # --------------------------------------------
    # Command Handlers
    # --------------------------------------------
    def do_load(self, sample_file):
        """load <sample_file>
        - Loads a sample file for processing
        IMPORTANT: use the fully qualified path to the file,
        ex.: C:\\samples\\sample.swf or /home/user/samples/sample.swf
        """

        try:
            self.swf = SWFObject(sample_file, ml=self.logger)
            print "[*] Sample {} loaded!".format(sample_file)
        except IOError as e:
            print "[x] Sample {} could not be loaded: {}".format(sample_file, e)

    def do_show_plugins(self, args):
        """show_plugins
        - Display information about the available (active) plugins
        """

        print
        print self.fm.show_active_plugins()

    def do_run_plugin(self, plugin_name):
        """run_plugin <plugin_name>
        - Executes the plugin named <plugin_name>
        """

        if not self.swf:
            print "[x] No sample loaded! Use the 'load' command first"
            return

        output = self.fm.run_plugin(plugin_name, swf=self.swf)
        print output

        self.plugins_done.add(plugin_name)

    def do_decompile(self, args):
        """decompile
        - Decompiles all methods
        This information can be queried from the 
        enriched SWFObject afterwards
        """

        if not self.swf:
            print "[x] No sample loaded! Use the 'load' command first"
            return

        dec = self.fm.run_plugin('Decompiler', swf=self.swf)

        if not dec:
            print "[x] Decompilation did not produce any results!"
            return

        # The decompiler's output will be used normally 
        # to enrich the SWFObject, like this:
        self.swf.decompiled_methods = dec
        self.has_decompilation = True
        print "[*] Decompilation available now."

        self.plugins_done.add('Decompiler')

    def do_strange_loops(self, args):
        """strange_loops
        - Finds loops with suspicious instructions
          e.g. a loop containing a `bitxor` instruction
        """

        # NOTE: this is an example of how to wrap the `run_plugin` 
        # command for convenience

        if not self.swf:
            print "[x] No sample loaded! Use the 'load' command first"
            return

        meth_loop = self.fm.run_plugin('SuspiciousLoops', swf=self.swf)

        print "The following methods contain suspicious loops."
        print "This may indicate encryption/encoding routines..."
        print

        for method_name in meth_loop:
            instance_name = self.swf.get_instance_for_method(method_name)
            if instance_name:
                print " - {}!{}".format(instance_name, method_name)
            else:
                print " - {}".format(method_name)

            if self.has_decompilation:
                try:
                    print "-" * 50
                    print
                    print self.swf.decompile_method(method_name)
                except Exception as e:
                    print "[x] Unable to decompile {}".format(method_name)

        self.plugins_done.add('SuspiciousLoops')

    def do_status(self, args):
        """status
        - Displays analysis session status
        """

        if not self.swf:
            print "[x] No sample loaded! Use the 'load' command first"
            return

        print "Sample file:", self.swf.filename
        print
        print "Embedded binary data:"
        for name, data in self.swf.binary_data.iteritems():
            print " - {} ({} bytes)".format(name, len(data))

        print
        print "Plugins already executed:"
        if not self.plugins_done:
            print " - No plugins executed yet"
        else:
            for p in self.plugins_done:
                print " - {}".format(p)

    # --------------------------------------------
    # Auxiliary
    # --------------------------------------------
    def _init_logging(self):
        """ Rotating log files """
        try:
            logging.basicConfig(format='%(asctime)s [%(levelname)s] %(module)s :: %(funcName)s: %(message)s',
                                level=logging.DEBUG)
            fmt = logging.Formatter('%(asctime)-12s [%(levelname)s] %(module)s :: %(funcName)s: %(message)s')

            handler = logging.handlers.RotatingFileHandler(
                'flashmingo.log',
                maxBytes=5 * 1024 * 1024,
                backupCount=5)

            handler.setLevel(logging.DEBUG)
            handler.setFormatter(fmt)

            ml = logging.getLogger('main')
            ml.addHandler(handler)

            return ml
        except Exception as e:
            print "Error initializing logging:"
            print e
            return None


def main():
    # This prevents some useless warnings
    # from polluting the screen ouput
    warnings.simplefilter("ignore")

    c = FlashmingoCmd()
    c.cmdloop()


if __name__ == "__main__":
    main()
