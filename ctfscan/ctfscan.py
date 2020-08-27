#!/usr/bin/python3
__version__ = "0.1"

import sys
import requests
import logging
from multiprocessing.dummy import Pool as ThreadPool

logging.basicConfig(format="", level=logging.INFO)
logger = logging.getLogger(__name__)

def scan(path):
    fullUrl = url.rstrip('\n') + path
    r = requests.get(fullUrl)
    if r.status_code != 404:
        logger.info(f"[ {r.status_code} ] {fullUrl}")

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: ctfscan url")

    url = sys.argv[1].rstrip("/")
    with open("./dic.txt") as f:
        data = f.readlines()

    pool = ThreadPool(processes=6)
    pool.map(scan, data)
    pool.close()
    pool.join()

if __name__ == '__main__':
    main()


