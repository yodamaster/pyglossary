# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'Tabfile'
description = 'Tabfile (txt, dic)'
extentions = ['.txt', '.tab', '.dic']
readOptions = []
writeOptions = [
    'writeInfo',
]

from pyglossary.text_reader import TextGlossaryReader


class Reader(TextGlossaryReader):
    def isInfoWord(self, word):
        return word.startswith('#')

    def fixInfoWord(self, word):
        return word.lstrip('#')

    def nextPair(self):
        if not self._file:
            raise StopIteration
        line = self._file.readline()
        if not line:
            raise StopIteration
        line = line.strip()## This also removed tailing newline
        if not line:
            return
        ###
        fti = line.find('\t') # first tab's index
        if fti==-1:
            log.error('Warning: line starting with "%s" has no tab!'%line[:10])
            return
        word = line[:fti]
        defi = line[fti+1:]#.replace('\\n', '\n')#.replace('<BR>', '\n').replace('\\t', '\t')
        ###
        if self._glos.getPref('enable_alts', True):
            word = word.split('|')
        ###
        defi = defi.decode('string_escape')## '\\n' -> '\n', '\\t' -> '\t'
        ###
        return word, defi



def write(glos, filename, writeInfo=True):
    return glos.writeTabfile(
        filename,
        writeInfo=writeInfo,
    )


