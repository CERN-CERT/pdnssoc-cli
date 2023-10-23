import click
from datetime import timedelta, datetime
import logging
from pymisp import PyMISP
from pathlib import Path
from pdnssoccli.utils import file as pdnssoc_file_utils

logger = logging.getLogger(__name__)



@click.command(help="Fetch IOCs from intelligence sources")
@click.option(
    'logging_level',
    '--logging',
    type=click.Choice(['INFO','WARN','DEBUG','ERROR']),
    default="INFO"
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
@click.pass_context
def fetch_iocs(ctx,
    **kwargs):

    correlation_config = ctx.obj['CONFIG']['correlation']

    # Set up MISP connections
    misp_connections = []
    for misp_conf in ctx.obj['CONFIG']["misp_servers"]:
        misp = PyMISP(misp_conf['domain'], misp_conf['api_key'], **misp_conf['conn_args'])
        if misp:
            misp_connections.append((misp, misp_conf['args'], misp_conf['periods']['tags']))

    domain_attributes_old = []
    domain_attributes_new = []
    ips_attributes_new = []
    ips_attributes_old = []


    # Get new attributes
    for misp, args, tag_periods in misp_connections:
        ips_to_validate = set()

        attributes = []

        # Keep configured tag names to exclude them from catch all
        configured_tags = []

        for tag in tag_periods:
            configured_tags.extend(tag['names'])

            if tag['delta']:
                misp_timestamp = datetime.now() - timedelta(**tag['delta'])
            else:
                misp_timestamp=None


            tag_attributes = misp.search(
                controller='attributes',
                type_attribute=[
                    'domain',
                    'domain|ip',
                    'hostname',
                    'hostname|port',
                    'ip-src',
                    'ip-src|port',
                    'ip-dst',
                    'ip-dst|port',
                ],
                to_ids=1,
                pythonify=True,
                tags=tag['names'],
                timestamp=misp_timestamp,
                **args
            )

            attributes.extend(tag_attributes)

        # Fetch catch all

        if misp_conf['periods']['generic']['delta']:
            misp_timestamp = datetime.now() - timedelta(**misp_conf['periods']['generic']['delta'])
        else:
            misp_timestamp=None

        catch_all_attributes = misp.search(
            controller='attributes',
            type_attribute=[
                'domain',
                'domain|ip',
                'hostname',
                'hostname|port',
                'ip-src',
                'ip-src|port',
                'ip-dst',
                'ip-dst|port',
            ],
            to_ids=1,
            pythonify=True,
            tags=["!" + tag for tag in configured_tags],
            timestamp=misp_timestamp,
            **args
        )

        attributes.extend(catch_all_attributes)

        for attribute in attributes:
            # Put to bucket according to attribute type
            match attribute.type:
                case 'domain' | 'hostname':
                    domain_attributes_new.append(attribute.value)
                case 'domain|ip':
                    domain_val, ip_val = attribute.value.split("|")
                    domain_attributes_new.append(domain_val)
                    ips_attributes_new.append(ip_val)
                case 'hostname|port':
                    hostname_val, _ = attribute.value.split("|")
                    domain_attributes_new.append(hostname_val)
                case 'ip-src' | 'ip-dst':
                    ips_attributes_new.append(attribute.value)
                case 'ip-src|port' | 'ip-dst|port':
                    ip_val, _ = attribute.value.split("|")
                    # Check if value in warninglist:
                    ips_to_validate.add(ip_val)

        # Validate ip|port attributes against warninglists
        warn_matches = misp.values_in_warninglist(list(ips_to_validate))

        if warn_matches:
            res = [i for i in list(ips_to_validate) if i not in warn_matches.keys()]
            ips_attributes_new.extend(res)

    # Check if domain ioc files already exist
    domains_file_path = correlation_config['malicious_domains_file']
    domains_file = Path(domains_file_path)

    if domains_file.is_file():
        # File exists, let's try to update it
        domains_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_domains_file']))
        for domain in domains_iter:
            domain_attributes_old.append(domain.strip())

    if set(domain_attributes_old) != set(domain_attributes_new):
        # We spotted a difference, let's overwrite the existing file
        with pdnssoc_file_utils.write_generic(domains_file) as fp:
            for attribute in list(set(domain_attributes_new)):
                fp.write("{}\n".format(attribute))

    # Check if ip ioc files already exist
    ips_file_path = correlation_config['malicious_ips_file']
    ips_file = Path(ips_file_path)

    if ips_file.is_file():
        # File exists, let's try to update it
        ips_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_ips_file']))
        for ip in ips_iter:
            ips_attributes_old.append(ip.strip())

    if set(ips_attributes_old) != set(ips_attributes_new):
        # We spotted a difference, let's overwrite the existing file
        with pdnssoc_file_utils.write_generic(ips_file) as fp:
            for attribute in list(set(ips_attributes_new)):
                fp.write("{}\n".format(attribute))

    logger.debug("Finished fetching of IOCs")
    logger.info("Currently {} domains and {} ips".format(len(set(domain_attributes_new).union(set(domain_attributes_new))), len(set(ips_attributes_new).union(set(ips_attributes_old)))))
