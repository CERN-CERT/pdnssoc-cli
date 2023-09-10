#!/usr/bin/python

import asyncio
import click
import logging
import yaml
from pdnssoccli.subcommands.fetch_iocs import fetch_iocs
from pdnssoccli.subcommands.correlate import correlate
from pdnssoccli.subcommands.utils import make_sync


logger = logging.getLogger("pdnssoccli")

def configure(ctx, param, filename):
    # Parse config file
    try:
        with open(filename) as config_file:
            parsed_config = yaml.safe_load(config_file)
    except:
        parsed_config = {}

    ctx.default_map = parsed_config


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


main.add_command(correlate)
main.add_command(fetch_iocs)

if __name__ == "__main__":
    asyncio.run(main())
