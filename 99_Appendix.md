# Appendices

## Appendix A: Using Sigmac to Convert Sigma Rules to Splunk

### Installing `sigma-tools` into a Python 3 Virtual Environment

To test `sigma-tools` locally, using a Python virtual environment is recommended,
as it allows you to install the required dependencies and tools in such a way
that the rest of your Python installation and system are not affected, and it
can be easily removed by deleting the folder.

We assume you already have Python 3 installed on your system before following
this guide.

1. Open your terminal application of choice (*nix terminal, or PowerShell)
1. Browse to a directory you wish to use for the experiment
1. Create the virtual environment: `python3 -m venv sigma-tools-venv`
1. Activate the virtual environment
  1. On Windows: `./sigma-tools-venv/bin/Activate.ps1`
  1. On *nix: `source sigma-tools-venv/bin/activate`
1. Install `sigmatools`: `python3 -m pip install sigmatools`
1. Test to make sure it works: `sigmac --help`

*Note:* If you leave/close the shell, the next time you want to use `sigmac` you
will need to activate the virtual environment again.

### Converting a rule to Splunk

*Note:* Assumes you are in a terminal with `sigmatools` installed and/or in
the virtual environment from above.

1. `sigmac --config splunk-corelight --target splunk <path-to-Sigma-YML-file>`
2. Prepend the output with any additional, environment-specific information, for
instance to indicate to Splunk which index(es) should be used for the search (e.g. `index=corelight`)

## Appendix B: Contributing to the Corelight Threat Hunting Guide

The Corelight Threat Hunting Guide is written and maintained on GitHub at
[https://github.com/corelight/threat-hunting-guide/](https://github.com/corelight/threat-hunting-guide/).
If you would like to report an issue, please raise an issue on the GitHub repository.

To submit new content, such as a Sigma query, or new or updated prose:

1. Fork the repository
1. Make your changes
1. Add yourself to the CREDITS file
1. Submit a pull request back to the main repository
