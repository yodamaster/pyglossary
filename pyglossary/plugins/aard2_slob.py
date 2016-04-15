# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'Aard2Slob'
description = 'Aard 2 (slob)'
extentions = ['.slob']
readOptions = []
writeOptions = [
    'compression',## values: 'bz2', 'zlib', 'lzma2'
]


def read(glos, filename): 
    from pyglossary.plugin_lib import slob
    with slob.open('test.slob') as slobObj:## slobObj is instance of Slob class
        for refIndex in range(len(slobObj)):
            blob = slobObj[refIndex]
            word = blob.key
            defi = blob.content
            glos.addEntry(word, defi)
    



def write(glos, filename, compression=None):
    from pyglossary.plugin_lib import slob
    with slob.Writer(
        filename,
        compression=compression,
    ) as slobWriter:
        for entry in glos:
            word = entry.getWord()
            defi = entry.getDefi()
            slobWriter.add(word, defi)













