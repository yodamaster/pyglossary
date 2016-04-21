# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'Omnidic'
description = 'Omnidic'
extentions = ['.omni', '.omnidic']
readOptions = ['dicIndex']
writeOptions = []


def read(glos, filename, dicIndex=16):
    initCwd = os.getcwd()
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
                word = parts[0]
                defi = ''.join(parts[1:])
                glos.addEntry(
                    word,
                    defi,
                )
    os.chdir(initCwd)


def write(glos, filename, dicIndex=16):
    if not isinstance(dicIndex, int):
        raise TypeError('Invalid argument to function writeOmnidic: filename=%s'%filename)
    if not os.path.isdir(filename):
        os.mkdir(filename)
    initCwd = os.getcwd()
    os.chdir(filename)

    indexFp = open(str(dicIndex), 'wb')

    for bucketIndex, bucket in enumerate(glos.iterEntryBuckets(100)):
        if bucketIndex==0:
            bucketFilename = '%s99'%dicIndex
        else:
            bucketFilename = '%s%s'%(
                dicIndex,
                bucketIndex * 100 + len(bucket) - 1,
            )

        indexFp.write('%s#%s#%s\n'%(
            bucket[0].getWord(),
            bucket[-1].getWord(),
            bucketFilename,
        ))

        bucketFileObj = open(bucketFilename, 'wb')
        for entry in bucket:
            word = entry.getWord()
            defi = entry.getDefi()
            defi = defi.replace('\n', '  ') ## FIXME
            bucketFileObj.write('%s#%s\n'%(word, defi))
        bucketFileObj.close()

    indexFp.close()
    os.chdir(initCwd)


def write2(glos, filename, dicIndex=16):
    """
        more complicated write function without glos.iterEntryBuckets
        more memory-efficient though
    """
    if not isinstance(dicIndex, int):
        raise TypeError('Invalid argument to function writeOmnidic: filename=%s'%filename)
    if not os.path.isdir(filename):
        os.mkdir(filename)
    initCwd = os.getcwd()
    os.chdir(filename)
    wordCount = len(glos)

    indexFp = open(str(dicIndex), 'wb')

    last100thWord = None ## word
    bucketFilename = None
    bucketFileObj = None

    for entryI, entry in enumerate(glos):
        word = entry.getWord()
        defi = entry.getDefi()
        defi = defi.replace('\n', '  ') ## FIXME

        if entryI % 100 == 0:
            last100thWord = word
            if entryI==0:
                bucketFilename = '%s99'%dicIndex
            else:
                bucketFilename = '%s%s'%(
                    dicIndex,
                    min(entryI + 99, wordCount-1)
                )
            if bucketFileObj:
                bucketFileObj.close()
            bucketFileObj = open(bucketFilename, 'wb')
        elif entryI % 100 == 99:
            indexFp.write(last100thWord + '#' + word + '#' + bucketFilename + '\n')
            last100thWord = None

        bucketFileObj.write('%s#%s\n'%(word, defi))

    if last100thWord:
        bucketFilename = '%s%s'%(dicIndex, wordCount-1)
        indexFp.write(last100thWord + '#' + word + '#' + bucketFilename + '\n')

    bucketFileObj.close()
    indexFp.close()

    os.chdir(initCwd)





