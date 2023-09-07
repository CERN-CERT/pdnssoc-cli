#!/usr/bin/python

import asyncio
import functools
import click
from datetime import datetime
import ipaddress
import json
import logging
from pathlib import Path
import jsonlines
from pymisp import PyMISP
import shutil
from .utils import file as pdnssoc_file_utils
from .utils import time as pdnssoc_time_utils
from .utils import correlation as pdnssoc_correlation_utils
from .utils import enrichment as pdnssoc_enrichment_utils
import yaml


logger = logging.getLogger("pdnssoccli")

def configure(ctx, param, filename):
    # Parse config file
    try:
        with open(filename) as config_file:
            parsed_config = yaml.safe_load(config_file)
    except:
        parsed_config = {}

    ctx.default_map = parsed_config


def make_sync(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

@click.group()
@click.option(
    '-c', '--config',
    type         = click.Path(dir_okay=False, file_okay=True),
    default      = "/etc/pdnssoc-cli/config.yml",
    callback     = configure,
    is_eager     = True,
    expose_value = False,
    help         = 'Read option defaults from the specified yaml file',
    show_default = True,
)
@click.pass_context
@make_sync
async def main(ctx,
    **kwargs
):
    ctx.ensure_object(dict)
    ctx.obj['CONFIG'] = ctx.default_map



@main.command(help="Correlate input files and output matches")
@click.argument(
    'files',
    nargs=-1,
    type=click.Path(
        file_okay=True,
        dir_okay=True,
        readable=True,
        allow_dash=True
    )
)
@click.option(
    'logging_level',
    '--logging',
    type=click.Choice(['INFO','WARN','DEBUG','ERROR']),
    default="INFO"
)
@click.option(
    'start_date',
    '--start-date',
    type=click.DateTime(formats=["%Y-%m-%dT%H:%M:%S"]),
    default=datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
)
@click.option(
    'end_date',
    '--end-date',
    type=click.DateTime(formats=["%Y-%m-%dT%H:%M:%S"]),
    default=datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
)
@click.option(
    'delete_on_success',
    '--delete-on-success',
    '-D',
    is_flag=True,
    help="Delete file on success.",
    default=False
)
@click.option(
    'correlation_output_file',
    '--output-dir',
    type=click.Path(
        file_okay=False,
        dir_okay=True,
        writable=True,
        allow_dash=True
    )
)
@click.option(
    'malicious_domains_file',
    '--malicious-domains-file',
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
)
@click.option(
    'malicious_ips_file',
    '--malicious-ips-file',
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
)
@make_sync
@click.pass_context
async def correlate(ctx,
    **kwargs):

    # Configure logging
    logging.basicConfig(
        level=ctx.obj['CONFIG']['logging_level']
    )

    # Parse json file and only keep alerts in range
    logging.info(
        "Parsing alerts from: {} to {}".format(
            kwargs.get('start_date'),
            kwargs.get('end_date')
        )
    )

    correlation_config = ctx.obj['CONFIG']['correlation']

    # Set up MISP connections
    misp_connections = []
    for misp_conf in ctx.obj['CONFIG']["misp_servers"]:
        misp = PyMISP(misp_conf['domain'], misp_conf['api_key'], True, debug=False)
        if misp:
            misp_connections.append(misp)


    # Set up domain and ip blacklists
    domain_attributes = []

    print(correlation_config)
    if 'malicious_domains_file' in correlation_config and correlation_config['malicious_domains_file']:
        domains_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_domains_file']))
        for domain in domains_iter:
            domain_attributes.append(domain.strip())
    else:
        for misp in misp_connections:
            attributes = misp.search(controller='attributes', type_attribute='domain', to_ids=1, pythonify=True)
            for attribute in attributes:
                domain_attributes.append(attribute.value)

    domain_attributes = list(set(domain_attributes))


    ip_attributes = []

    if 'malicious_ips_file' in correlation_config and correlation_config['malicious_ips_file']:
        ips_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_ips_file']))
        for attribute in ips_iter:
            try:
                network = ipaddress.ip_network(attribute.strip(), strict=False)
                ip_attributes.append(network)
            except ValueError:
                logging.warning("Invalid malicious IP value {}".format(attribute))
    else:
        ips_iter = misp.search(controller='attributes', type_attribute=['ip-src','ip-dst'], to_ids=1, pythonify=True)

        for attribute in ips_iter:
            try:
                network = ipaddress.ip_network(attribute.value, strict=False)
                ip_attributes.append(network)
            except ValueError:
                logging.warning("Invalid malicious IP value {}".format(attribute.value))

    total_matches = []
    total_matches_minified = []

    for file in kwargs.get('files'):
        file_path = Path(file)

        if file_path.is_file():

            file_iter, is_minified =  pdnssoc_file_utils.read_file(file_path)

            if file_iter:
                matches = pdnssoc_correlation_utils.correlate_file(
                    file_iter,
                    kwargs.get("start_date"),
                    kwargs.get("end_date"),
                    set(domain_attributes),
                    set(ip_attributes),
                    is_minified
                )
                logger.info("Found {} matches in {}".format(len(matches), file_path.absolute()))

                if is_minified:
                    total_matches_minified.extend(matches)
                else:
                    total_matches.extend(matches)

            if kwargs.get('delete_on_success'):
                file_path.unlink()
        else:
            # Recursively handle stuff
            for nested_path in file_path.rglob('*'):
                if nested_path.is_file():

                    file_iter, is_minified =  pdnssoc_file_utils.read_file(nested_path)

                    if file_iter:
                        matches = pdnssoc_correlation_utils.correlate_file(
                            file_iter,
                            kwargs.get("start_date"),
                            kwargs.get("end_date"),
                            set(domain_attributes),
                            set(ip_attributes),
                            is_minified
                        )

                        logger.info("Found {} matches in {}".format(len(matches), nested_path.absolute()))

                        if is_minified:
                            total_matches_minified.extend(matches)
                        else:
                            total_matches.extend(matches)

            if kwargs.get('delete_on_success'):
                shutil.rmtree(file)


    enriched = await pdnssoc_enrichment_utils.enrich_logs(total_matches, misp_connections, False)
    enriched_minified = await pdnssoc_enrichment_utils.enrich_logs(total_matches_minified, misp_connections, True)

    # Output to directory
    # Write full matches to matches.json
    
    with jsonlines.open(Path(correlation_config['output_dir'], "matches.json"), mode='a') as writer:
        for document in enriched + enriched_minified:
            writer.write(document)


if __name__ == "__main__":
    asyncio.run(main())
