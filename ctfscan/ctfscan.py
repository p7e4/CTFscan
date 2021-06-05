#!/usr/bin/python3
__version__ = "1.3.3"

import sys
import requests
import logging
from multiprocessing.dummy import Pool as ThreadPool
import argparse
import os

logging.basicConfig(format="", level=logging.INFO)
logger = logging.getLogger(__name__)

datapath = os.path.abspath(os.path.dirname(__file__))

def scan(path):
    try:
        r = requests.get(url + path, verify=False, timeout=10)
    except Exception as e:
        logger.error(f"[{e}] {path}")
    else:
        if r.status_code != 404 and str(r.status_code) not in args.exclude:
            for i in args.exclude:
                if i in r.text: return

            logger.info(f"[{r.status_code}] {path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("-e", "--exclude", action="append", help="exclude status_code or content", default=[])
    parser.add_argument("-t", "--thread", default=6, help="thread, default 6")
    global args
    global url
    global data
    args = parser.parse_args()
    url = args.url[:-1] if args.url.endswith("/") else args.url
    with open(f"{datapath}/data/data.txt") as f:
        data = f.read()

    pool = ThreadPool(processes=args.thread)
    pool.map(scan, data.split("\n"))
    pool.close()
    pool.join()


if __name__ == '__main__':
    main()




