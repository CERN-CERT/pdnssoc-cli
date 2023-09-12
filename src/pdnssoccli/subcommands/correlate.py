import click
from datetime import datetime
import ipaddress
from pdnssoccli.subcommands.utils import make_sync
from pdnssoccli.utils import file as pdnssoc_file_utils
from pdnssoccli.utils import time as pdnssoc_time_utils
from pdnssoccli.utils import correlation as pdnssoc_correlation_utils
from pdnssoccli.utils import enrichment as pdnssoc_enrichment_utils
import logging
import jsonlines
from pymisp import PyMISP
from pathlib import Path

logger = logging.getLogger("pdnssoccli")

@click.command(help="Correlate input files and output matches")
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
    default=None
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

    correlation_config = ctx.obj['CONFIG']['correlation']

    # Configure logging
    logging.basicConfig(
        level=ctx.obj['CONFIG']['logging_level']
    )

    # Determine start date
    if not kwargs.get('start_date'):
        if 'last_correlation_pointer_file' in correlation_config:
            last_correlation_path = Path(correlation_config['last_correlation_pointer_file'])
            if last_correlation_path.is_file():
                correlation_last , _  = pdnssoc_file_utils.read_file(Path(correlation_config['last_correlation_pointer_file']))
                for line in correlation_last:
                    timestamp = pdnssoc_time_utils.parse_rfc3339_ns(
                        line
                    )
                    start_date = timestamp
                    break
            else:
                logger.warning("Last correlation file at {} not existing. Will be recreated".format(correlation_config['last_correlation_pointer_file']))
                start_date = datetime.now()
        else:
            start_date = datetime.now()
    else:
        start_date = kwargs.get('start_date')
    end_date = kwargs.get('end_date')


    # Parse json file and only keep alerts in range
    logging.info(
        "Parsing alerts from: {} to {}".format(
            start_date,
            end_date
        )
    )

    # Set up MISP connections
    misp_connections = []
    for misp_conf in ctx.obj['CONFIG']["misp_servers"]:
        misp = PyMISP(misp_conf['domain'], misp_conf['api_key'], True, debug=False)
        if misp:
            misp_connections.append(misp)


    # Set up domain and ip blacklists
    domain_attributes = []
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
                    start_date,
                    end_date,
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
                            start_date,
                            end_date,
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

    to_output = enriched + enriched_minified
    to_output = sorted(to_output, key=lambda d: d['timestamp'])

    with jsonlines.open(Path(correlation_config['output_dir'], "matches.json"), mode='a') as writer:
        for document in to_output:
            writer.write(document)

    # if new correlations, keep last timestamp
    if to_output:
        last_correlation = to_output[-1]['timestamp']
    else:
        last_correlation = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    with pdnssoc_file_utils.write_generic(correlation_config['last_correlation_pointer_file']) as fp:
            fp.write("{}\n".format(last_correlation))