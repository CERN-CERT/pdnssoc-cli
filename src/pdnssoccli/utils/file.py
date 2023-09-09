import gzip
import logging

logger = logging.getLogger("pdnssoccli")


def read_gzip(file_name):
    f = gzip.open(file_name, 'rb')
    return f

def read_json(file_name):
    f = open(file_name, mode='rb')
    return f

def read_generic(file_name):
    f = open(file_name, mode='rt')
    return f

def read_file(file_path):
    logging.info("Parsing {}".format(file_path.absolute()))

    is_minified = False
    file_iter = None
    if file_path.suffix == ".json":
        file_iter = read_json(file_path.absolute())
    elif file_path.suffix == ".gz":
        file_iter = read_gzip(file_path.absolute())
    elif file_path.suffix == ".gz_minified":
        file_iter = read_gzip(file_path.absolute())
        is_minified = True
    elif file_path.suffix == ".txt":
        file_iter = read_generic(file_path.absolute())
    else:
        logging.warning("File {} is not in valid format".format(file_path))

    return file_iter, is_minified

def write_generic(file_name):
    f = open(file_name, mode='w')
    return f
