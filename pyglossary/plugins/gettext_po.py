# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'GettextPo'
description = 'Gettext Source (po)'
extentions = ['.po',]
readOptions = []
writeOptions = []

from polib import escape as po_escape
from polib import unescape as po_unescape
from pyglossary.file_utils import fileCountLines


class Reader(object):
    def __init__(self, glos, hasInfo=True):
        self._glos = glos
        self._filename = ''
        self._file = None
        self._len = None
    def open(self, filename):
        self._filename = filename
        self._file = open(filename)
    def close(self):
        if not self._file:
            return
        try:
            self._file.close()
        except:
            log.exception('error while closing file "%s"'%self._filename)
        self._file = None
    def __len__(self):
        if self._len is None:
            log.warn('Try not to use len(reader) as it takes extra time')
            self._len = fileCountLines(
                self._filename,
                newline='\nmsgid',
            )
        return self._len
    def __iter__(self):
        word = ''
        defi = ''
        msgstr = False
        wordCount = 0
        for line in self._file:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            if line.startswith('msgid '):
                if word:
                    yield Entry(word, defi) ; wordCount += 1
                    word = ''
                    defi = ''
                word = po_unescape(line[6:])
                msgstr = False
            elif line.startswith('msgstr '):
                if msgstr:
                    log.error('msgid omitted!')
                defi = po_unescape(line[7:])
                msgstr = True
            else:
                if msgstr:
                    defi += po_unescape(line)
                else:
                    word += po_unescape(line)
        if word:
            yield Entry(word, defi) ; wordCount += 1
        self._len = wordCount


def write(glos, filename):
    fp = open(filename, 'wb')
    fp.write('#\nmsgid ""\nmsgstr ""\n')
    for inf in glos.infoKeys():
        fp.write('"%s: %s\\n"\n'%(inf, glos.getInfo(inf)))
    for entry in glos:
        word = entry.getWord()
        defi = entry.getDefi()
        fp.write('msgid %s\nmsgstr %s\n\n'%(
            po_escape(word),
            po_escape(defi),
        ))
    fp.close()

