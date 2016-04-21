# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'MtuxMdic'
description = 'SQLite(MDic m2, Sib sdb)'
extentions = ['.m2', '.sdb']
readOptions = []
writeOptions = []

from sqlite3 import connect

infoKeys = [
    'dbname',## name OR dbname? FIXME
    'author',
    'version',
    'direction',
    'origLang',
    'destLang',
    'license',
    'category',
    'description',
]

class Reader(object):
    def __init__(self, glos):
        self._glos = glos
        self._clear()

    def _clear(self):
        self._filename = ''
        self._con = None
        self._cur = None
        
    def open(self, filename):
        self._filename = filename
        self._con = connect(filename)
        self._cur = self._con.cursor()
        self.loadInfo()

    def close(self):
        self._cur.close()
        self._con.close()
        self._clear()

    def loadInfo(self):
        for key in infoKeys:
            try:
                self._cur.execute('select %s from dbinfo'%key)
            except:
                continue
            value = self._cur.fetchone()[0].encode('utf8')
            if not value:
                continue
            self._glos.setInfo(key, value)

    def __len__(self):
        self._cur.execute('select count(*) from word')
        return self._cur.fetchone()[0]

    def getLastId(self):
        self._cur.execute('select max(id) from word')
        return self._cur.fetchone()[0]

    def __iter__(self):
        limit = 500
        '''
        limit   time    memory
        100     1.77    25164
        500     1.75    25136
        1000    1.76    25140
        2000    1.78    25724
        '''
        lastId = self.getLastId()
        for startId in range(0, lastId+1, limit):
            self._cur.execute('select * from word where id between %s and %s order by id'%(
                startId,
                startId + limit - 1,
            ))
            for row in self._cur.fetchall():
                try:
                    word = row[1].encode('utf8')
                    defi = row[2].encode('utf8')
                except:
                    log.exception('error while encoding row id=%s'%row[0])
                else:
                    yield Entry(word, defi)




def write_2(glos, filename):
    import pyglossary.alchemy as alchemy
    alchemy.writeSqlite(glos, filename)

def write_3(glos, filename):
    import pyglossary.exir as exir
    exir.writeSqlite_ex(glos, filename)
    return True

def write(glos, filename):
    if os.path.exists(filename):
        os.remove(filename)
    con = connect(filename)
    cur = con.cursor()
    for line in glos.iterSqlLines(
        infoKeys=infoKeys,
        newline='<BR>',
        transaction=False,
    ):
        try:
            cur.execute(line)
        except:
            log.exception('error executing sqlite query:')
            log.error('Error while executing: '+line)
            continue
    
    cur.close()
    con.close()
    return True

