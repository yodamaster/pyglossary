from formats_common import *
#from .bgl_reader import BglReader as Reader

enable = True
format = 'BabylonBgl'
description = 'Babylon (bgl)'
extentions = ['.bgl']
readOptions = [
    'resPath',## str, directory path
    'defaultEncodingOverwrite',## str, encoding
    'sourceEncodingOverwrite',## str, encoding
    'targetEncodingOverwrite',## str, encoding
    'msgLogPath',## str, file path
    'rawDumpPath',## str, file path
    'decodedDumpPath',## str, file path
    'unpackedGzipPath',## str, file path
    'searchCharSamples',## bool
    'charSamplesPath',## str, file path
    'testMode',## bool
    'noControlSequenceInDefi',## bool
    'strictStringConvertion',## bool
    'collectMetadata2',## bool
    'oneLineOutput',## bool
    'processHtmlInKey',## bool
    'keyRStripChars',## str, list of characters to strip (from right side)
]
writeOptions = []
supportsAlternates = True
#progressbar = DEFAULT_YES

## FIXME: document type of read/write options (that would be specified in command line)


def read(glos, filename, **options):
    from .bgl_reader import BglReader
    glos.setDefaultDefiFormat('h')
    reader = BglReader(filename)
    if not reader.open(**options):
        raise IOError('can not open BGL file "%s"'%filename)
    n = len(reader)
    ui = glos.ui
    if not isinstance(n, int):
        ui = None
    if ui:
        ui.progressStart()

    ##############################################
    step = 2000
    for index, entry in enumerate(reader):
        glos.addEntryObj(entry)
        if ui and index % step == 0:
            rat = float(index)/n
            ui.progress(rat)
    if ui:
        ui.progressEnd()
    reader.close()




