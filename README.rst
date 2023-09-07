===========
pdnssoc-cli
===========

Correlate dnstap files with MISP threat intelligence.

This tool parses JSON and compressed files created by `go-dnscollector <https://github.com/dmachard/go-dnscollector>`_.


Installation
============

``pdnssoc-cli`` can be fetched from the following sources:

PyPi
----
    .. code-block:: bash

        pip install pdnssoc-cli


Configuration
=============

Configuration can be provided using the ``--config`` flag in yaml format:

    .. code-block:: yaml

        logging_level: "INFO"

        misp_servers:
            - domain: "https://example-misp-instance.com"
                api_key: "API_KEY"

        correlation:
            output_dir: ./output_dir/
            malicious_domains_file: ./misp_domains.txt
            malicious_ips_file: ./misp_ips.txt

If no config flag is provided, the default file is ``/etc/pdnssoc-cli/config.yml``.


Usage
=====

    .. code-block::

        Usage: pdnssoc_cli [OPTIONS] COMMAND [ARGS]...

        Options:
            -c, --config FILE  Read option defaults from the specified yaml file
                                [default: /etc/pdnssoc-cli/config.yml]
            --help             Show this message and exit.

        Commands:
            correlate  Correlate input files and output matches


Use-cases
=========

Correlate `go-dnscollector <https://github.com/dmachard/go-dnscollector>`_ output and produce alerts:
