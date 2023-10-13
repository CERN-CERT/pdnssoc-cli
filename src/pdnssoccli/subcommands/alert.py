import click
from datetime import datetime
import ipaddress
from pdnssoccli.subcommands.utils import make_sync
from pdnssoccli.utils import file as pdnssoc_file_utils
from pdnssoccli.utils import time as pdnssoc_time_utils
from pdnssoccli.utils import alert as pdnssoc_alerting_utils
import logging
import jsonlines
from pymisp import PyMISP
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

@click.command(help="Raise alerts for spotted incidents")
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
    default=None
)
@click.pass_context
def alert(ctx,
    **kwargs):

    alerting_config = ctx.obj['CONFIG']['alerting']
    correlation_config = ctx.obj['CONFIG']['correlation']
    alerting_start_dt = datetime.now()

    # iterate through alert configs enabled
    for alert_type, alert_conf in ctx.obj['CONFIG']['alerting'].items():
        logger.info("Enabling {} alerting".format(alert_type))
        # Set up mailing here


    if not kwargs.get('files'):
        files = [correlation_config['output_dir']]
    else:
        files = kwargs.get('files')

    if not kwargs.get('start_date'):
        if 'last_alerting_pointer_file' in alerting_config:
            start_date = pdnssoc_time_utils.get_time_from_pointer(alerting_config['last_alerting_pointer_file'])

        if not start_date:
            start_date = alerting_start_dt
    else:
        start_date = kwargs.get('start_date')

    if not kwargs.get('end_date'):
        end_date = datetime.now()
    else:
        end_date = kwargs.get('end_date')


    pending_alerts = {}
    for file in files:
        file_path = Path(file)
        if file_path.is_file():
            file_iter, _ =  pdnssoc_file_utils.read_file(file_path)

            if file_iter:
                try:
                    pending_alerts = pdnssoc_alerting_utils.alerts_from_file(
                        file_iter,
                        start_date,
                        end_date,
                        pending_alerts
                    )

                except:
                    logger.error("Failed to parse {}, skipping".format(file))
                    continue
        else:
            for nested_path in file_path.rglob('*'):
                if nested_path.is_file():
                    file_iter, _ =  pdnssoc_file_utils.read_file(nested_path)

                    if file_iter:
                        try:
                            pending_alerts = pdnssoc_alerting_utils.alerts_from_file(
                                file_iter,
                                start_date,
                                end_date,
                                pending_alerts
                            )

                        except:
                            logger.error("Failed to parse {}, skipping".format(nested_path))
                            continue

    # Send summary to pdnssoc service maintainers
    pdnssoc_alerting_utils.email_alerts(pending_alerts, alerting_config['email'], summary=True)

    #Send mails to each of the responsibles for a sensor
    pdnssoc_alerting_utils.email_alerts(pending_alerts, alerting_config['email'], summary=False)

    # Update the last alert file
    with pdnssoc_file_utils.write_generic(alerting_config['last_alerting_pointer_file']) as fp:
        fp.write("{}\n".format(end_date.strftime("%Y-%m-%dT%H:%M:%S")))