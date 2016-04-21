# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'Omnidic'
description = 'Omnidic'
extentions = ['.omni', '.omnidic']
readOptions = ['dicIndex']
writeOptions = []


def read(glos, filename, dicIndex=16):
    os.chdir(filename)
    try:
        fp = open(str(dicIndex))
    except:
        log.error('bad index: %s'%dicIndex)
        return False
    for f in [l.split('#')[-1] for l in fp.read().split('\n')]:
        if f=='':
            continue
        for line in open(f).read().split('\n'):
            if line=='':
                pass
            elif line[0]=='#':
                pass
            else:
                parts = line.split('#')
                glos.data.append([parts[0], ''.join(parts[1:])])
    os.chdir(initCwd)


def write(glos, filename, dicIndex=16):
    if not isinstance(dicIndex, int):
        raise TypeError('Invalid argument to function writeOmnidic: filename=%s'%filename)
    if not os.path.isdir(filename):
        os.mkdir(filename)
    initCwd = os.getcwd()
    os.chdir(filename)
    wordCount=len(glos.data)
    fileCountM1=int(wordCount/100) # file count mines one
    indexFp = open(str(dicIndex), 'wb')
    for i in xrange(fileCountM1):
        if i==0:
            fileName = str(dicIndex) + '99'
        else:
            fileName = str(dicIndex) + str(i) + '99'
        indexFp.write(glos.data[100*i][0] + '#' + glos.data[100*i+99][0] + '#' + fileName + '\n')
        fp = open(fileName, 'wb')
        for j in xrange(100):
            (w, m) = glos.data[100*i+j][:2]
            m = m.replace('\n', '  ') ### FIXME
            fp.write('%s#%s\n'%(w, m))
        fp.close(); del fp, fileName
    endNum = wordCount % 100
    if endNum > 0:
        fileName=str(dicIndex)+str(fileCountM1)+str(endNum-1)
        fp = open(fileName, 'wb')
        indexFp.write(glos.data[100*fileCountM1][0]+'#'+glos.data[100*fileCountM1+endNum-1][0]+'#'+fileName+'\n')
        for j in xrange(endNum):
            (w, m) = glos.data[100*fileCountM1+j][:2]
            m = m.replace('\n', '  ') ### FIXME
            fp.write('%s#%s\n'%(w, m))
        fp.close(); del fp, fileName
        indexFp.close(); del indexFp
    os.chdir(initCwd)





