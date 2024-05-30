import json
import logging
import smtplib
import jinja2
from datetime import timedelta
import pytz
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from pdnssoccli.utils.time import parse_rfc3339_ns

logger = logging.getLogger("pdnssoccli")


def alerts_from_file(file_iter, start_date, end_date, client_hash):
    for line in file_iter:
        try:
            match = json.loads(line.strip())
        except json.JSONDecodeError:
            logger.warning("Ignoring line due to unrecognized format:{}".format(line))
            continue

        timestamp = parse_rfc3339_ns(match['timestamp'])

        if start_date < timestamp <= end_date:
            # Define the client
            # If client_ip exists then
            client_name = match['client_name']
            client_ip = match['client_ip']

            client_hash.setdefault(client_name, {})
            client_hash[client_name].setdefault(client_ip, {})

            client_hash[client_name][client_ip].setdefault(match['query'], {'first_occurence': timestamp, 'events':{}, 'answers': set()})

            # Handle MISP events
            for event in match['correlation']['misp']['events']:

                client_hash[client_name][client_ip][match['query']]['events'][event['uuid']] = event

                # Signify matching IOC

                for answer in match['answers']:
                        client_hash[client_name][client_ip][match['query']]['answers'].add(
                            "{} ({})".format(
                                answer['rdata'],
                                answer['rdatatype']
                            )
                        )

                #client_hash[client_name][client_ip][event['ioc']]['query'].append("match['query']")

                if client_hash[client_name][client_ip][match['query']]['first_occurence'] > timestamp:
                    client_hash[client_name][client_ip][match['query']]['first_occurence'] = timestamp

    return client_hash

def email_alerts(alerts, config, summary = False):

    if not alerts:
        logger.warn("No alerts to dispatch")
        return None
    # Define a custom filter to enumerate elements
    def enumerate_filter(iterable):
        return enumerate(iterable, 1)  # Start counting from 1
    # Connecting to the mail server
    smtp = smtplib.SMTP(config['server'], config['port'])

    template_file = Path(config['template'])

    # Set up template
    email_template_loader = jinja2.FileSystemLoader(searchpath = template_file.parent)
    email_template_env = jinja2.Environment(loader = email_template_loader)
    # To allow the use of the timedelta and pytz inside the Jinja2 templates
    email_template_env.globals.update(timedelta = timedelta)
    email_template_env.globals.update(pytz = pytz)
    # Add the custom filter to the Jinja2 environment
    email_template_env.filters['enumerate'] = enumerate_filter

    email_template = email_template_env.get_template(template_file.name)

    outgoing_mailbox = []

    if summary:
        # Load all alerts in one template
        email_body = email_template.render(alerts=alerts)

        msg_root = MIMEMultipart('related')
        msg_root['Subject'] = str(config["subject"])
        msg_root['From'] = config["from"]
        msg_root['To'] = config["summary_to"]
        msg_root['Reply-To'] = config["from"]
        msg_root.preamble = 'This is a multi-part message in MIME format.'
        msg_alternative = MIMEMultipart('alternative')
        msg_root.attach(msg_alternative)
        msg_text = MIMEText(str(email_body), 'html', 'utf-8')
        msg_alternative.attach(msg_text)

        outgoing_mailbox.append(msg_root)

    else:
        # Group emails per destination in email.mappings
        for sensor, sensor_data in alerts.items():
            if config['mappings']:
               for mapping in config['mappings']:
                   if mapping['client_id'] == sensor:
                       email_body = email_template.render(alerts={sensor:sensor_data})
                       msg_root = MIMEMultipart('related')
                       msg_root['Subject'] = str(config["subject"])
                       msg_root['From'] = config["from"]
                       msg_root['To'] = mapping['contact']
                       msg_root['Reply-To'] = config["from"]
                       msg_root.preamble = 'This is a multi-part message in MIME format.'
                       msg_alternative = MIMEMultipart('alternative')
                       msg_root.attach(msg_alternative)
                       msg_text = MIMEText(str(email_body), 'html', 'utf-8')
                       msg_alternative.attach(msg_text)
                       outgoing_mailbox.append(msg_root)
               else:
                   logger.warning("Sensor {} not configured for email alerting".format(sensor))



    for mail in outgoing_mailbox:
        # Send the email
        smtp.sendmail(mail['From'], mail['To'], mail.as_string())
        logging.debug('Sending email notification to {}'.format(mail['To']))

    smtp.quit()
