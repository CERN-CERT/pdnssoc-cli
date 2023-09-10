import json
import ipaddress
import logging
from . import time as pdnssoc_time_utils
from cachetools import cached
from cachetools.keys import hashkey

logger = logging.getLogger("pdnssoccli")

@cached(cache={}, key=lambda query, domain_set: hashkey(query))
def correlate_query(query, domain_set):
    if query in domain_set:
        return True
    else:
        return False

@cached(cache={}, key=lambda answer, ip_set: hashkey(answer['rdata']))
def correlate_answer(answer, ip_set):
    if answer['rdatatype'] == 'A' or answer['rdatatype'] == 'AAAA':
        ip_answer = ipaddress.ip_address(answer['rdata'])
        for network in ip_set:
            if ip_answer in network:
                return True
    return False



def correlate_events(lines, shared_data):
    (start_date, end_date, domain_attributes, ip_attributes, is_minified) = shared_data
    total_matches = []


    for line in lines:
        try:
            match = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring line due to unrecognized format:{}".format(line))
            continue

        match_found = False

        if is_minified:
            timestamp = pdnssoc_time_utils.parse_rfc3339_ns(match['timestamp'])
            query = match['query']
            answers = match['answers']
        else:
            timestamp = pdnssoc_time_utils.parse_rfc3339_ns(
                match['dnstap']["timestamp-rfc3339ns"]
            )
            query = match['dns']['qname']
            answers = match['dns']['resource-records']['an']

        # parse timestamp
        if start_date < timestamp <= end_date:
            if correlate_query(query, domain_attributes):
                logging.debug("Matched {}".format(match))
                total_matches.append(match)
                continue

            for answer in answers:
                if correlate_answer(answer, ip_attributes):
                    total_matches.append(match)
                    break

    return total_matches

def correlate_file(file_iter, start_date, end_date, domain_attributes, ip_attributes, is_minified):
    total_matches = []
    total_matches = correlate_events(file_iter, (start_date, end_date, domain_attributes, ip_attributes, is_minified))
    return total_matches
