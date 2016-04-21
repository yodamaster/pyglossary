# -*- coding: utf-8 -*-

from formats_common import *

enable = True
format = 'Treedict'
description = 'TreeDict'
extentions = ['.tree', '.treedict']
readOptions = []
writeOptions = []


def write(glos, filename, archive='tar.bz2', sep=os.sep):
    if os.path.exists(filename):
        if os.path.isdir(filename):
            if os.listdir(filename)!=[]:
                log.warn('Warning: directory "%s" is not empty.')
        else:
            raise IOError('"%s" is not a directory')
    for item in glos.data:
        if item[0]=='':
            log.error('empty word')
            continue
        chars = list(item[0])
        try:
            os.makedirs(filename + os.sep + sep.join(chars[:-1]))
        except:
            pass
        try:
            open('%s%s%s.m'%(
                filename,
                os.sep,
                sep.join(chars),
            ), 'wb').write(item[1])
        except:
            log.exception()
    if archive:
        if archive=='tar.gz':
            (output, error) = subprocess.Popen(
                ['tar', '-czf', filename+'.tar.gz', filename],
                stdout=subprocess.PIPE
            ).communicate()
        elif archive=='tar.bz2':
            (output, error) = subprocess.Popen(
                ['tar', '-cjf', filename+'.tar.bz2', filename],
                stdout=subprocess.PIPE
            ).communicate()
        elif archive=='zip':
            (output, error) = subprocess.Popen(
                ['zip', '-r', filename+'.zip', filename],
                stdout=subprocess.PIPE
            ).communicate()
        else:
            log.error('Undefined archive format: "%s"'%archive)
        try:
            shutil.rmtree(filename, ignore_errors=True)
        except:
            pass


