#!/usr/bin/python3
from importlib.resources import files
import itertools
import argparse
import asyncio
import aiohttp
import difflib
import string
import random
import os
import re

__version__ = "0.1.1"

async def fuzzScan(session, url, paths):
    while paths:
        path = paths.pop(0)
        try:
            async with session.get(url.format(fuzz=path), ssl=False, allow_redirects=False) as resp:
                msg = [f"[{resp.status}]", f"[payload: {path}]"]
                for i in resp.headers:
                    if i in ("Content-Length", "Location", "Set-Cookie"):
                        msg.append(f"[{i}: {resp.headers[i]}]")
                print(" ".join(msg))
        except Exception as e:
            print(f"payload `{path}` error {e}")

async def dirScan(session, url, paths, notFoundPage):
    def compare(data):
        if notFoundPage.get("ratio"):
            notFoundPage["matcher"].set_seq2(data)
            return notFoundPage["matcher"].quick_ratio() < notFoundPage["ratio"]
        return notFoundPage["content"] != data

    while paths:
        path = paths.pop(0).removeprefix("/")
        if not path or path.startswith("#"): continue
        try:
            async with session.get(f"{url}/{path}", ssl=False, allow_redirects=False) as resp:
                if resp.status != 404 and  (resp.status != notFoundPage["status"] or compare(await resp.read())):
                    print(f"[{resp.status}] /{path}")
        except Exception as e:
            print(f"{type(e).__name__}: `{url}/{path}`: {e}")

async def dynamicDetect(session, url):
    async def query(path):
        async with session.get(f"{url}/{path}", ssl=False, allow_redirects=False) as resp:
            return {
                "status": resp.status,
                "content": await resp.read()
            }
    try:
        a, b = [await query(''.join(random.choices(string.ascii_letters + string.digits, k=24))) for _ in range(2)]
    except Exception as e:
        exit(f"{type(e).__name__}: {e}")
    else:
        # TODO: add Location?
        if a["content"] != b["content"]:
            a["matcher"] = difflib.SequenceMatcher()
            a["matcher"].set_seq1(a["content"])
            a["matcher"].set_seq2(b["content"])
            a["ratio"] = round(a["matcher"].quick_ratio(), 3)
            print(f"dynamic 404 page detect, ratio={a['ratio']}")
            if a["ratio"] <= 0.6:
                exit("Error: dynamic page content radio too low")
        return a

async def main():
    epilog = 'Fuzz mode: ctfscan "http://host/?q={fuzz}" -f "a-zA-Z0-9, 1" # equal to "\\w, 1"'
    parser = argparse.ArgumentParser(prog="ctfscan", epilog=epilog)
    parser.add_argument("url")
    parser.add_argument("-c", "--file", help="custom dic file")
    # parser.add_argument("-e", "--exclude", action="append", default=[], help="exclude status_code")
    parser.add_argument("-f", "--fuzz", help="fuzz mode")
    parser.add_argument("-H", "--header", action="append", default=[], help="custom header(s)")
    parser.add_argument("-V", "--version", action="version", version=__version__)
    args = parser.parse_args()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
    }
    for header in args.header:
        k, v = header.split(": ", 1)
        headers[k] = v

    if args.fuzz:
        if not (n:=re.match(r"(.*),\s*(\d+)", args.fuzz)):
            exit("fuzz pattern format error")
        elif "{fuzz}" not in args.url:
            exit("`{fuzz}` not found in url")
        strings = n.group(1)
        for k, v in {
            "A-Z": string.ascii_uppercase,
            "a-z": string.ascii_lowercase,
            "0-9": string.digits,
            r"\w": string.ascii_letters + string.digits,
            r"\d": string.digits
        }.items():
            strings = strings.replace(k, v, 1)
        paths = ["".join(i) for i in (itertools.product(list(set(strings)), repeat=int(n.group(2))))]

    elif file:=args.file:
        if not os.path.exists(file):
            if not os.path.exists(file:=files("ctfscan").joinpath(file)):
                exit(f"Error: `{file}` not found")
        with open(file) as f:
            paths = f.read().split("\n")
    else:
        paths = files("ctfscan").joinpath("default.txt").read_text().split("\n")

    url = args.url.removesuffix("/")
    async with aiohttp.ClientSession(headers=headers) as session:
        if args.fuzz: 
            return await asyncio.gather(*[fuzzScan(session, url, paths) for _ in range(5)])

        notFoundPage = await dynamicDetect(session, args.url)
        await asyncio.gather(*[dirScan(session, url, paths, notFoundPage) for _ in range(5)])

def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        exit("user aborted")

if __name__ == "__main__":
    run()
