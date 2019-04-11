# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO
# The tool for all your Flash analysis needs... with a funny name!

import os
import sys
import imp
import logging
import logging.handlers
import yaml

from resources import flashmingo_banner


class Flashmingo:
    """FLASHMINGO main class

    FLASHMINGO is essentially a harness for plugins 
    operating on SWFObjects (representing a SWF file)
    """

    def __init__(self, ml=None):
        self.cfg = None
        self.log_level = ''
        self.ml = ml
        self.plugins_dir = ''
        self.plugins = []
        self.config_file = 'cfg.yml'

        self._init_core()

        # Log the banner :)
        self.ml.info(flashmingo_banner)

    def _init_core(self):
        """Initializes the core functionality

        - Logging (rotating file)
        - Configuration (read from cfg.yml)
        - Plugin system
        """

        if not self.ml:
            # No external logging facility
            # Flashmingo will use its own
            self.ml = self._init_logging()
            if not self.ml:
                print "Failed to initialize logging. Exiting..."
                sys.exit(1)

        self.cfg = self._read_config()

        if not self.cfg:
            self.ml.error('Failed to open the configuration file. Exiting...')
            sys.exit(1)

        self._register_plugins()

    def _init_logging(self):
        """Rotating log files

        This is used only if the Flashmingo object 
        is instantiated without an external logging facility
        """

        try:
            logging.basicConfig(format='%(asctime)s [%(levelname)s] %(module)s :: %(funcName)s: %(message)s',
                                level=self.log_level)
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

    def _read_config(self):
        try:
            with open(self.config_file, 'r') as f:
                cfg = yaml.load(f)
        except Exception as e:
            self.ml.error(e)
            return None

        # Set some important values from the 
        # YAML config file
        system = cfg['system']

        self.plugins_dir = system['plugins_dir']
        self.ml.info("Setting plugin directory: {}".format(
            self.plugins_dir))

        debug = cfg['logging']['debug']

        if debug:
            self.log_level = logging.DEBUG
        else:
            self.log_level = logging.INFO

        return cfg

    def _get_plugin_info_by_name(self, plugin_name):
        for p in self.plugins:
            if p['name'] == plugin_name:
                return p

        return None

    def _register_plugins(self):
        self.ml.info("Registering plugins...")

        if not self.plugins_dir:
            self.ml.error('Failed to get plugins_dir')
            sys.exit(1)

        # Go through all directories reading the 
        # plugins config files
        for curr_path, _, filenames in os.walk(self.plugins_dir):
            for filename in filenames:
                if filename == "manifest.yml":
                    manifest_path = os.path.join(curr_path, filename)

                    try:
                        with open(manifest_path, 'r') as f:
                            manifest = yaml.load(f)
                    except Exception as e:
                        # We will just log and continue
                        # The plugin will not be registered...
                        msg = "Failed to read manifest {}".format(
                            manifest_path)
                        self.ml.error(msg)
                        self.ml.error(e)

                    plugin_name = manifest['name']
                    active = manifest['active']
                    description = manifest['description']
                    returns = manifest['returns']

                    if not active:
                        msg = "Plugin {} deactivated in its config".format(
                            plugin_name)
                        self.ml.info(msg)
                        continue

                    msg = "Registering plugin {}".format(
                        plugin_name)
                    self.ml.info(msg)

                    plugin_info = dict()
                    plugin_info['name'] = plugin_name

                    # This is the path containing the 
                    # plugin's code and manifest
                    # ex. 'plugins/dangerous_apis'
                    plugin_info['location'] = curr_path

                    mod_path = curr_path.replace(os.sep, '.')
                    mod_name = "{}.plugin".format(mod_path)
                    plugin_info['mod_name'] = mod_name

                    plugin_info['description'] = description
                    plugin_info['returns'] = returns

                    self.plugins.append(plugin_info)

    def show_banner(self):
        """ Now FLASHMINGO is complete :)
        
        Prints the banner.
        This is the very definition of 
        "minimalistic wrapper".
        """

        print flashmingo_banner

    def show_active_plugins(self):
        """Convenience wrapper.

        Displays a list of active plugins names
        """

        print "Active plugins"
        print "--------------"
        print

        for p in self.plugins:
            if not p:
                continue

            print "Plugin name: {}".format(p['name'])
            print "  - desc: {}".format(p['description'])
            print "  - returns: {}".format(p['returns'])
            print

    def run_plugin(self, plugin_name, swf=None, logger=None, **kwargs):
        """Run an active plugin

        Args:
            plugin_name (str): dough
            swf: An SWF # FIXME
            logger (Logging.Logger): A logger object # FIXME

        Returns:
            plugin's output
        """

        if not swf:
            self.ml.error("No swf object!")
            return

        pi = self._get_plugin_info_by_name(plugin_name)

        if not pi:
            msg = "Plugin {} not found!".format(plugin_name)
            self.ml.error(msg)
            return

        #
        # imp library magic
        mod_name = pi['mod_name']
        loc_plugin = pi['location']
        full_loc = os.path.join(loc_plugin, 'plugin.py')

        plugin_mod = imp.load_source(mod_name, full_loc)

        # Arguments are permissive here to support all plugins 
        # with one interface but restricted on the plugin itself
        try:
            plugin = plugin_mod.Plugin(swf=swf, ml=logger, **kwargs)
        except TypeError as e:
            fmt = "Plugin {} called with wrong argument?".format(
                plugin_name)
            self.ml.error(fmt)
            self.ml.error(e)

            return None

        output = plugin.run()

        return output
