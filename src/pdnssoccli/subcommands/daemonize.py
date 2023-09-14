from pathlib import Path
from pdnssoccli.subcommands.utils import make_sync

from pdnssoccli.subcommands.fetch_iocs import fetch_iocs
from pdnssoccli.subcommands.correlate import correlate

import click
import logging

import schedule
import time
import threading

logger = logging.getLogger(__name__)

@click.command(help="Run in daemonized mode according to configuration")
@make_sync
@click.pass_context
def daemonize(ctx, **kwargs):
    logger.info("Starting pdnssoc-cli in daemonized mode")

    daemon_config = ctx.obj['CONFIG']['schedules']
    correlation_config = ctx.obj['CONFIG']['correlation']

    def run_threaded(job_func):
        job_thread = threading.Thread(target=job_func)
        job_thread.start()

    def daemonized_fetch_iocs():
        ctx.invoke(fetch_iocs)

    def daemonized_correlate():
        ctx.invoke(correlate)

    def daemonized_retro():
        ctx.invoke(correlate, **{'retro_lookup': True, 'files':[correlation_config['archive_dir']]})


    # Establish scheduled tasks according to documentation
    if 'fetch_iocs' in daemon_config:
        logger.info("Scheduled [fetch-iocs] with a {} minutes period".format(daemon_config['fetch_iocs']['interval']))
        schedule.every(daemon_config['fetch_iocs']['interval']).minutes.do(run_threaded, daemonized_fetch_iocs)

    if 'correlation' in daemon_config:
        logger.info("Scheduled [correlation] with a {} minutes period".format(daemon_config['correlation']['interval']))
        schedule.every(daemon_config['correlation']['interval']).minutes.do(run_threaded, daemonized_correlate)

    if 'retro' in daemon_config:
        logger.info("Scheduled [retro] with a {} minutes period".format(daemon_config['retro']['interval']))
        schedule.every(daemon_config['retro']['interval']).minutes.do(run_threaded, daemonized_retro)

    # First execution of all scheduled on startup
    schedule.run_all()

    while True:
        schedule.run_pending()
        time.sleep(1)