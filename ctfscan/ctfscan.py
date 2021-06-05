#!/usr/bin/python3
__version__ = "1.3.4"

import sys
import requests
import logging
from multiprocessing.dummy import Pool as ThreadPool
import argparse

logging.basicConfig(format="", level=logging.INFO)
logger = logging.getLogger(__name__)

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
    args = parser.parse_args()
    url = args.url[:-1] if args.url.endswith("/") else args.url

    pool = ThreadPool(processes=args.thread)
    pool.map(scan, data.split("\n"))
    pool.close()
    pool.join()

data = """\
/flag
/flag.php
/flag.txt
/.git
/.git/HEAD
/.git/index
/.git/config
/.git/description
/README.MD
/README.md
/README
/.gitignore
/.svn
/.svn/wc.db
/.svn/entries
/.hg
/.DS_Store
/WEB-INF/web.xml
/WEB-INF/src/
/WEB-INF/classes
/WEB-INF/lib
/WEB-INF/database.propertie
/CVS/Root
/CVS/Entries
/.bzr/
/_viminfo
/.viminfo
/phpinfo.php
/robots.txt
/test.php
/.htaccess
/.bash_history
/.svn/
/.git/
/.hg/
/.index.php.swp
/.index.php
/.index.php~
/index.php.bak
/index.php.bak_Edietplus
/index.php.~1~
/index.php
/index.php.rar
/index.php.zip
/index.php.7z
/index.php.tar.gz
/index.php.txt
/index.php~
/index.bak
/login.php
/register.php
/upload.php
/phpinfo.php
/ssrf.php
/a.php
/b.php
/c.php
/d.php
/e.php
/f.php
/g.php
/h.php
/i.php
/j.php
/k.php
/l.php
/m.php
/n.php
/o.php
/p.php
/q.php
/r.php
/s.php
/t.php
/u.php
/v.php
/w.php
/x.php
/y.php
/z.php
/0.php
/1.php
/2.php
/3.php
/4.php
/5.php
/6.php
/7.php
/8.php
/9.php
/www.zip
/www.rar
/www.7z
/www.tar.gz
/www.tar
/web.zip
/web.rar
/web.7z
/web.tar.gz
/web.tar
/plus
/0
/1
/05/
/s8qq.txt
/s8log.txt
/s8wwwroot.rar
/s8web.rar
/dede
/admin
/edit
/Fckeditor
/ewebeditor
/bbs
/Editor
/manage
/shopadmin
/web_Fckeditor
/login,asp
/webadmin
/admin/WebEditor
/admin/daili/webedit
/login/
/database/
/tmp/
/manager/
/manage/
/web/
/admin/
/shopadmin/
/wp-includes/
/edit/
/editor/
/1.zip
/1.rar
/1.7z
/1.tar.gz
/1.tar
/tar.zip
/tar.rar
/web1.zip
/web1.rar
/123.zip
/123.rar
/code.zip
/code.rar
/root.zip
/root.rar
/wwwroot.zip
/wwwroot.rar
/backup.zip
/backup.rar
/mysql.bak
/a.sql
/b.sql
/db.sql
/bdb.sql
/ddb.sql
/mysql.sql
/dump.sql
/data.sql
/backup.sql
/backup.sql.gz
/backup.sql.bz2
/backup.zip"""

if __name__ == '__main__':
    main()




