from cachetools import cached
from cachetools.keys import hashkey
import logging

logger = logging.getLogger("pdnssoccli")

@cached(cache={}, key=lambda misp_connection, value, types: hashkey(misp_connection.root_url, value, tuple(types)))
def query_misp(misp_connection, value, types):
    r = misp_connection.search(
        controller="attributes",
        value=value,
        include_context=True,
        type_attribute=types,
        include_correlations=False,
        pythonify=True,
        debug=False,
        to_ids=True,
        enforce_warninglist=True,
        include_event_tags=True
    )

    return r

def build_misp_events(misp_response, misp_connection, encountered_events, query):
    misp_events = []

    for attribute in misp_response:
        event = attribute.Event
        if not event.uuid in encountered_events:
            tags = []
            for tag in attribute.tags:
                tags.append(
                    {
                        "colour": tag.colour,
                        "name": tag.name
                    }
                )

            misp_events.append(
                {
                    'uuid': event.uuid,
                    'info': event.info,
                    'id': event.id,
                    'server': misp_connection.root_url,
                    'event_url': "{}/events/view/{}".format(misp_connection.root_url, event.id),
                    #'num_iocs': event.attribute_count,
                    'publication': event.date.strftime("%Y-%m-%d"),
                    'organization': event.Orgc.name,
                    'comment': attribute.comment,
                    'tags': tags,
                    'ioc': attribute.value,
                    'ioc_type': attribute.type
                }
            )

            encountered_events.add(event.uuid)

    return misp_events, encountered_events


def enrich_logs(logs, misp_connections, is_minified):
    enriched_results = []

    for log in logs:
        if is_minified:
            query = log['query']
            answers = log['answers']
            timestamp = log['timestamp']
            query_ip = log['client']
            client_id = log['client_id']
        else:
            query = log['dns']['qname']
            answers = log['dns']['resource-records']['an']
            timestamp = log['dnstap']['timestamp-rfc3339ns']
            query_ip = log['network']['query-ip']
            client_id = log['dnstap']['identity']


        misp_events = []
        encountered_events = set()

        for misp_connection, args in misp_connections:
            # Search for query
            r = query_misp(misp_connection, query, ['domain', 'domain|ip', 'hostname', 'hostname|port', 'url'])

            query_events, encountered_events = build_misp_events(
                r,
                misp_connection,
                encountered_events,
                query
            )

            misp_events.extend(query_events)

            # Search for each answer
            for answer in answers:
                if answer['rdatatype'] == 'A' or answer['rdatatype'] == 'AAAA':
                    r = query_misp(
                        misp_connection,
                        "{}".format(answer['rdata']),
                        [
                            'domain',
                            'domain|ip',
                            'hostname',
                            'hostname|port',
                            'ip-src',
                            'ip-src|port',
                            'ip-dst',
                            'ip-dst|port',
                        ]
                    )

                    r_url = query_misp(
                        misp_connection,
                        "http%://{}%".format(answer['rdata']),
                        [
                            'url'
                        ]
                    )

                    answer_events, encountered_events = build_misp_events(
                        r+r_url,
                        misp_connection,
                        encountered_events,
                        answer['rdata']
                    )

                    misp_events.extend(answer_events)


        enriched_results.append(
            {
                "client_ip": query_ip,
                "client_name": client_id,
                "timestamp": timestamp,
                "query": query,
                "answers": answers,
                "correlation": {
                    "misp": {
                        "events": misp_events
                    }
                }
            }
        )


    return enriched_results
