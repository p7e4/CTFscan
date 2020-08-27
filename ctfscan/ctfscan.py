#!/usr/bin/python3
__version__ = "1.0"

import sys
import requests
import logging
from multiprocessing.dummy import Pool as ThreadPool

logging.basicConfig(format="", level=logging.INFO)
logger = logging.getLogger(__name__)

data = r"""\
/flag
/flag.php
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
/%3f
/%3f~
/.%3f.swp
/.%3f.swo
/.%3f.swn
/.%3f.swm
/.%3f.swl
/_viminfo
/.viminfo
/%3f~
/%3f~1~
/%3f~2~
/%3f~3~
/%3f.save
/%3f.save1
/%3f.save2
/%3f.save3
/%3f.bak_Edietplus
/%3f.bak
/%3f.back
/phpinfo.php
/robots.txt
/test.php
/.htaccess
/.bash_history
/.svn/
/.git/
/.hg/
/.index.php.swp
/index.php.bak
/.index.php~
/index.php.bak_Edietplus
/index.php.~
/index.php.~1~
/index.php
/index.php~
/index.php.rar
/index.php.zip
/index.php.7z
/index.php.tar.gz
/index.php.txt
/login.php
/register.php
/upload.php
/phpinfo.php
/t.php
/1.php
/l.php
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
/backup.zip

"""

def scan(path):
    fullUrl = url.rstrip('\n') + path
    r = requests.get(fullUrl)
    if r.status_code != 404:
        logger.info(f"[ {r.status_code} ] {fullUrl}")

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: ctfscan url")

    global url
    url = sys.argv[1].rstrip("/")
    
    pool = ThreadPool(processes=6)
    pool.map(scan, data.split("\n"))
    pool.close()
    pool.join()

if __name__ == '__main__':
    main()


