# FLASHMINGO

## Install

Install the Python (2.7) packages listed in `requirements.txt`.

You can use the following command: `pip install -r requirements.txt`

If you want to use the decompilation functionality you need to install [Jython](https://www.jython.org/). Ubuntu/Debian users can issue `apt install jython`

Clone the project or download the zip file.


## What

FLASHMINGO is an analysis framework for SWF files. The tool automatically triages suspicious Flash files and guides the further analysis process, freeing precious resources in your team. You can easily incorporate FLASHMINGO’s analysis modules into your workflow.


## Why

To this day forensic investigators and malware analysts must deal with suspicious SWF files. If history repeats itself the security threat may even become bigger beyond Flash’s end of life in 2020. Systems will continue to support a legacy file format that is not going to be updated with security patches anymore. Automation is the best way to deal with this issue and this is where FLASHMINGO can help you. FLASHMINGO is an analysis framework to automatically process SWF files that enables you to flag suspicious Flash samples and analyze them with minimal effort. It integrates into various analysis workflows as a stand-alone application or a powerful library. Users can easily extend the tool’s functionality via custom Python plugins.


## How

### Architecture

FLASHMINGO is designed with simplicity in mind. It reads a SWF file and creates an object (`SWFObject`) representing its contents and structure. Afterwards FLASHMINGO runs a series of plugins acting on this `SWFObject` and returning their values to the main program.

Below a mandatory ASCII art flow diagram:

```
                                                 +----------+
                                                 |          |
                       +------------+----------->+ PLUGIN 1 +------------+
                       |            |            |          |            |
                       |            |            +----------+            |
                       |            |                                    |
                       |            |            +----------+            |
                       |            |            |          |            |
+---------+            |            +----------->+ PLUGIN 2 +--------+   |
|SWF FILE +----------->+ FLASHMINGO |            |          |        |   |
+---------+            |            |            +----------+        |   |
                       |            |                                |   |
                       |            |                                |   |
                       |            |                                |   |
                       |            |                          +-----v---v-+
                       |            |                          |           |
                       |            |                          |           |
                       +-----+------+------------------------->+ SWFOBJECT |
                             ^                                 |           |
                             |                                 |           |
                             |                                 +-----+-----+
                             |                                       |
                             |                                       |
                             |                                       |
                             +---------------------------------------+

```

When using FLASHMINGO as a library in your own projects, you only need to take care of two kind of objects:

- one or many `SWFObject`(s), representing the sample(s)
- a `Flashmingo` object. This acts essentially as a harness connecting plugins and `SWFObject`(s).


## Plugins!

FLASHMINGO plugins are stored in their own directories under... you guessed it: `plugins`
When a `Flashmingo` object is instantiated, it goes through this directory and process all plugins' manifests. Should this indicate that the plugin is active, this is registered for later use. At the code level, this means that a small `plugin_info` dictionary is added to the `plugins` list.

Plugins are invoked via the `run_plugin` API with two arguments:

- the plugin's name
- the `SWFObject` instance

Optionally, most of the plugins allow you to pass your own *user data*. This is plugin dependent (read the documentation) and it can be more easily be explained with an example. 
The default plugin `SuspiciousNames` will search all constant pools for strings containing *suspicious* substrings (for example: 'overflow', 'spray', 'shell', etc.) There is a list of common substrings already hard-coded in the plugin so that it can be used `as-is`. However, you may pass a list of your own defined substrings, in this case via the `names` parameter.


Code example:

```python
fm = Flashmingo()
print fm.run_plugin('DangerousAPIs', swf=swf)
print fm.run_plugin('SuspiciousNames', swf=swf, names=['spooky'])
```


### Default plugins

FLASHMINGO ships with some useful plugins out of the box:

- binary_data
- dangerous_apis
- decompiler
- suspicious_constants
- suspicious_loops
- suspicious_names
- template :)


### Extending FLASHMINGO

A template plugin is provided for easy development.
Extending FLASHMINGO is rather straightforward. Follow these simple steps:

- Copy the template
- Edit the manifest
- Override the `run` method
- Add your custom code

You are ready to go :)


## FLASHMINGO as a library

### API

- See the `docs` directory for autogenerated documentation
- See FireEye's blog post for an example


## Front-ends

- Console



## Create Documentation

`$ pip install sphinxcontrib-napoleon`

After setting up Sphinx to build your docs, enable napoleon in the Sphinx conf.py file:

In `conf.py`, add napoleon to the extensions list

`extensions = ['sphinxcontrib.napoleon']`

Use sphinx-apidoc to build your API documentation:

`$ sphinx-apidoc -f -o docs/source projectdir`

This creates `.rst` files for Sphinx to process

`$ make html`

That's it! :)
