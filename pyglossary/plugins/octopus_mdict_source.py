# -*- coding: utf-8 -*-
## http://www.octopus-studio.com/download.en.htm

from formats_common import *

enable = True
format = 'OctopusMdictSource'
description = 'Octopus MDict Source'
extentions = ['.mtxt']
readOptions = []
writeOptions = []

def read(glos, filename):
    glos.data = []
    text = open(filename).read()
    text = text.replace('\r\n', '\n')
    text = text.replace('entry://', 'bword://')
    for section in text.split('</>'):
        lines = section.strip().split('\n')
        if len(lines) < 2:
            continue
        glos.data.append((
            lines[0],
            '\n'.join(lines[1:]),
        ))


def write(glos, filename):
    glos.writeTxt(
        ('\r\n', '\r\n</>\r\n'),
        filename=filename,
        writeInfo=False,
        rplList=[
            ('bword://', 'entry://'),
        ],
        ext='.mtxt',
        head='',
    )


