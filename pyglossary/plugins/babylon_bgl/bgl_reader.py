# -*- coding: utf-8 -*-
##
## Copyright © 2008-2016 Saeed Rasooli <saeed.gnu@gmail.com> (ilius)
## Copyright © 2011-2012 kubtek <kubtek@gmail.com>
## This file is part of PyGlossary project, http://github.com/ilius/pyglossary
## Thanks to Raul Fernandes <rgfbr@yahoo.com.br> and Karl Grill for reverse engineering
##
## This program is a free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3, or (at your option)
## any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program. Or on Debian systems, from /usr/share/common-licenses/GPL
## If not, see <http://www.gnu.org/licenses/gpl.txt>.

debugReadOptions = {
    'searchCharSamples',## bool
    'collectMetadata2',## bool
    'writeGz',## bool
    'charSamplesPath',## str, file path
    'msgLogPath',## str, file path
    'rawDumpPath',## str, file path
    'unpackedGzipPath',## str, file path
}
readOptions = [
    'resPath',## str, directory path
    'defaultEncodingOverwrite',## str, encoding
    'sourceEncodingOverwrite',## str, encoding
    'targetEncodingOverwrite',## str, encoding

    'noControlSequenceInDefi',## bool
    'strictStringConvertion',## bool
    'processHtmlInKey',## bool
    'keyRStripChars',## str, list of characters to strip (from right side)
] + sorted(debugReadOptions)


import io
file = io.BufferedReader


import gzip
import re

from formats_common import *
from pyglossary.text_utils import (
    binStrToInt,
    excMessage,
    isASCII,
    formatByteStr,
)

from pyglossary.xml_utils import xml_escape

import pyglossary.gregorian as gregorian

from .bgl_info import (
    infoKeysByCode,
    infoKeyDecodeMethods,
    charsetInfoDecode,
)
from .bgl_pos import partOfSpeechByCode
from .bgl_text import *


if os.sep=='/': ## Operating system is Unix-like
    tmpDir = '/tmp'
elif os.sep=='\\': ## Operating system is ms-windows
    tmpDir = os.getenv('TEMP')
else:
    raise RuntimeError('Unknown path separator(os.sep=="%s") ! What is your operating system?'%os.sep)


charsetDecodePattern = re.compile(b'(<charset\\s+c\\=[\'\"]?(\\w)[\'\"]?>|</charset>)', re.I)


class BGLGzipFile(gzip.GzipFile):
    """
        gzip.GzipFile class without CRC check.

        We redefined one method - _read_eof.
        It prints a warning when CRC code does not match.
        The original method raises an exception in this case.
        Some dictionaries do not use CRC code, it is set to 0.
    """
    def __init__(
        self,
        fileobj=None,
        closeFileobj=False,
        **kwargs
    ):
        gzip.GzipFile.__init__(self, fileobj=fileobj, **kwargs)
        self.closeFileobj
    def close(self)
        if self.closeFileobj:
            self.fileobj.close()
    def _read_eof(self):
        from gzip import read32
        # We've read to the end of the file, so we have to rewind in order
        # to reread the 8 bytes containing the CRC and the file size.
        # We check the that the computed CRC and size of the
        # uncompressed data matches the stored values. Note that the size
        # stored is the true file size mod 2**32.
        self.fileobj.seek(-8, 1)
        crc32 = read32(self.fileobj)
        isize = read32(self.fileobj) ## may exceed 2GB
        if crc32 != self.crc:
            log.warning('CRC check failed %s != %s' % (hex(crc32), hex(self.crc)))
        elif isize != (self.size & 0xffffffff):
            raise IOError('Incorrect length of data produced')



class Block(object):
    def __init__(self):
        self.data = b''
        self.type = ''
        # block offset in the gzip stream, for debugging
        self.offset = -1
    def __str__(self):
        return 'Block type=%s, length=%s, len(data)=%s'%(self.type, self.length, len(self.data))

class FileOffS(file):
    """
        A file class with an offset.

        This class provides an interface to a part of a file starting at specified offset and
        ending at the end of the file, making it appear an independent file.
        offset parameter of the constructor specifies the offset of the first byte of the
        modeled file.
    """
    def __init__(self, filename, offset=0):
        fp = open(filename, 'rb')
        file.__init__(self, fp)
        self._fp = fp
        self.offset = offset
        self.filesize = os.path.getsize(filename)
        file.seek(self, offset) ## OR self.seek(0)
    def close(self):
        self._fp.close()
    def seek(self, pos, whence=0):## position, whence
        if whence==0:## relative to start of file
            file.seek(
                self,
                max(0, pos) + self.offset,
                0,
            )
        elif whence==1:## relative to current position
            file.seek(
                self,
                max(
                    self.offset,
                    self.tell() + pos,
                ),
                0
            )
        elif whence==2:## relative to end of file
            file.seek(self, pos, 2)
        else:
            raise ValueError('FileOffS.seek: bad whence=%s'%whence)
    def tell(self):
        return file.tell(self) - self.offset

class DefinitionFields(object):
    """
        Fields of entry definition

        Entry definition consists of a number of fields.
        The most important of them are:
        defi - the main definition, mandatory, comes first.
        part of speech
        title
    """
    nameByCode = {
    
    
    }
    def __init__(self):
        self.bytesByCode = {}
        #self.strByCode = {}

        self.encoding = None # encoding of the definition
        self.singleEncoding = True # true if the definition was encoded with a single encoding
        
        self.defi = None ## main definition part of defi, bytes
        self.u_defi = None ## main part of definition, str

        self.partOfSpeech = None # string representation of the part of speech, utf-8

        self.title = None ## bytes
        self.u_title = None ## str

        self.title_trans = None ## bytes
        self.u_title_trans = None ## str

        self.transcription_50 = None ## bytes
        self.u_transcription_50 = None ## str
        self.transcription_50_code = None

        self.transcription_60 = None ## bytes
        self.u_transcription_60 = None ## str
        self.transcription_60_code = None

        self.field_1a = None ## bytes
        self.u_field_1a = None ## str

        self.field_07 = None
        self.field_06 = None
        self.field_13 = None


class BglReader(object):

    ##############################################################################
    """
    Dictionary properties
    ---------------------

    Dictionary (or glossary) properties are textual data like glossary name,
    glossary author name, glossary author e-mail, copyright message and
    glossary description. Most of the dictionaries have these properties set.
    Since they contain textual data we need to know the encoding.
    There may be other properties not listed here. I've enumerated only those that
    are available in Babylon Glossary builder.

    Playing with Babylon builder allows us detect how encoding is selected.
    If global utf-8 flag is set, utf-8 encoding is used for all properties.
    Otherwise the target encoding is used, that is the encoding corresponding to
    the target language. The chars that cannot be represented in the target encoding
    are replaced with question marks.

    Using this algorithm to decode dictionary properties you may encounter that
    some of them are decoded incorrectly. For example, it is clear that the property
    is in cp1251 encoding while the algorithm says we must use cp1252, and we get
    garbage after decoding. That is OK, the algorithm is correct. You may install
    that dictionary in Babylon and check dictionary properties. It shows the same
    garbage. Unfortunately, we cannot detect correct encoding in this case
    automatically. We may add a parameter the will overwrite the selected encoding,
    so the user may fix the encoding if needed.
    """

    def __init__(self, glos):## no more arguments
        self._glos = glos
        self._filename = ''
        self.info = odict()
        self.numEntries = None
        ####
        self.sourceLang = ''
        self.targetLang = ''
        ##
        self.defaultCharset = ''
        self.sourceCharset = ''
        self.targetCharset = ''
        ##
        self.sourceEncoding = None
        self.targetEncoding = None
        ####
        self.bglNumEntries = None
        self.wordLenMax = 0
        self.defiLenMax = 0
        ##
        self.metadata2 = None
        self.rawDumpFile = None
        self.msgLogFile = None
        self.samplesDumpFile = None
        ##
        self.stripSlashAltKeyPattern = re.compile(r'(^|\s)/(\w)', re.U)
        self.specialCharPattern = re.compile(r'[^\s\w.]', re.U)
        self.charRefStatPattern = re.compile(b'(&#\\w+;)', re.I)
        ###
        self.file = None
        # offset of gzip header, set in self.open()
        self.gzipOffset = None
        # must be a in RRGGBB format
        self.partOfSpeechColor = '007000'
        self.resFiles = []

    def __len__(self):
        if self.numEntries is None:
            log.warning('len(reader) called while numEntries=None')
            return 0
        return self.numEntries

    def createResDir(self, resPath):
        if not resPath:
            # resPath is not specified.
            # Try directories like:
            # self._filename + '_files'
            # self._filename + '_files_0'
            # self._filename + '_files_1'
            # self._filename + '_files_2'
            # ...
            # use the temp directory if we cannot write to the dictionary directory
            i = -1
            while True:
                if i == -1:
                    resPath = '%s_files%s'%(self._filename, os.sep)
                else:
                    resPath = '%s_files_%s%s'%(self._filename, i, os.sep)
                if not exists(resPath) or isdir(resPath):
                    break
                i += 1
            if not exists(resPath):
                try:
                    os.mkdir(resPath)
                except IOError:
                    log.exception('error while creating resource directory "%s"'%resPath)
                    resPath = self.createResDirInTemp()
        else:
            if not exists(resPath):
                try:
                    os.mkdir(resPath)
                except IOError:
                    log.exception('error while creating resource directory "%s"'%resPath)
                    resPath = self.createResDirInTemp()
            else:
                if not isdir(resPath):
                    log.error('%s is not a directory'%resPath)
                    resPath = self.createResDirInTemp()
        return resPath

    def createResDirInTemp(self):
        resPath = join(tmpDir, os.path.basename(self._filename) + '_files') + os.sep
        if not isdir(resPath):
            os.mkdir(resPath)
        log.warning('using temp resource directory "%s"'%resPath)
        return resPath

    # open .bgl file, read signature, find and open gzipped content
    # self.file - ungzipped content
    def open(
        self,
        filename,
        defaultEncodingOverwrite = None,
        sourceEncodingOverwrite = None,
        targetEncodingOverwrite = None,
        resPath = None,
        noControlSequenceInDefi = False,
        strictStringConvertion = False,
        # process keys and alternates as HTML
        # Babylon does not interpret keys and alternates as HTML text,
        # however you may encounter many keys containing character references and html tags.
        # That is clearly a bug of the dictionary.
        # We must be very careful processing HTML tags in keys, not damage normal keys.
        # This option should be disabled by default, enabled explicitly by user.
        # Namely this option does the following:
        # - resolve character references
        # - strip HTML tags
        processHtmlInKey = False,
        # a string of characters that will be stripped from the end of the key (and alternate)
        # see str.rstrip function
        keyRStripChars = None,
        **kwargs
    ):
        if kwargs:
            for key in kwargs:
                if key in debugReadOptions:
                    log.error(
                        'BGL Reader: option "%s" is only usable in debug mode'%key
                        ', add -v4 to enable debug mode'
                    )
                else:
                    log.error('BGL Reader: invalid option "%s"'%key)
            return False

        self._filename = filename
        self.defaultEncodingOverwrite = defaultEncodingOverwrite
        self.sourceEncodingOverwrite = sourceEncodingOverwrite
        self.targetEncodingOverwrite = targetEncodingOverwrite
        self.resPath = self.createResDir(resPath)
        self.noControlSequenceInDefi = noControlSequenceInDefi
        self.strictStringConvertion = strictStringConvertion
        self.processHtmlInKey = processHtmlInKey
        self.keyRStripChars = keyRStripChars

        if not self.openGzip():
            return False

        if not self.readInfo():
            return False

        self.setGlossaryInfo()

        return True


    def openGzip(self):
        with open(self._filename, 'rb') as bglFile:
            if not bglFile:
                log.error('file pointer empty: %s'%bglFile)
                return False
            head = bglFile.read(6)

        if len(head)<6 or not head[:4] in (b'\x12\x34\x00\x01', b'\x12\x34\x00\x02'):
            log.error('invalid header: %s'%head[:6])
            return False

        self.gzipOffset = gzipOffset = binStrToInt(head[4:6])
        log.debug('Position of gz header: %s'%gzipOffset)

        if gzipOffset < 6:
            log.error('invalid gzip header position: %s'%gzipOffset)
            return False

        self.file = BGLGzipFile(
            fileobj=FileOffS(self._filename, gzipOffset),
            closeFileobj=True,
        )

        return True



    def readInfo(self):
        """
            read meta information about the dictionary: author, description, source and target languages, etc
            (articles are not read)
        """
        self.numEntries = 0
        self.numBlocks = 0
        deferred_block2_num = 0
        block = Block()
        while not self.isEndOfDictData():
            if not self.readBlock(block):
                break
            self.numBlocks += 1
            if not block.data:
                continue
            word = ''
            #defi = ''
            if block.type==0:
                self.readType0(block)
            elif block.type in (1, 7, 10, 11, 13):
                self.numEntries += 1
            elif block.type==2:
                if not self.readType2(block, 1):
                    deferred_block2_num += 1
            elif block.type==3:
                self.readType3(block)
            else:## Unknown block.type
                log.debug('Unkown Block type "%s", data_length=%s, number=%s'%(
                    block.type,
                    len(block.data),
                    self.numBlocks,
                ))
        self.file.seek(0)
        ################
        self.detectEncoding()

        if deferred_block2_num > 0:
            # process deferred type 2 blocks
            log.debug('processing type 2 blocks, second pass')
            while not self.isEndOfDictData():
                if not self.readBlock(block):
                    break
                if not block.data:
                    continue
                if block.type==2:
                    self.readType2(block, 2)
            self.file.seek(0)

        #######

        log.debug('numEntries = %s'%self.numEntries)
        if self.bglNumEntries != self.numEntries:
            # There are a number of cases when these numbers do not match.
            # The dictionary is OK, and these is no doubt that we might missed an entry.
            # self.bglNumEntries may be less than the number of entries we've read.
            log.warning('bglNumEntries=%s, numEntries=%s'%(self.bglNumEntries, self.numEntries))


        self.numBlocks = 0

        # remove resource directory if it's empty
        if len(os.listdir(self.resPath))==0:
            try:
                os.rmdir(self.resPath)
            except:
                log.exception('error creating resource directory "%s"'%self.resPath)

        return True

    def setGlossaryInfo(self, glos):
        glos = self._glos
        ###
        glos.setInfo('sourceLang', self.sourceLang)
        glos.setInfo('targetLang', self.targetLang)
        ###
        glos.setInfo('sourceCharset', 'UTF-8')
        glos.setInfo('targetCharset', 'UTF-8')
        ###
        glos.resPath = self.resPath
        ###
        for key, value in self.info.items():
            if key in {
                'creationTime',
                'middleUpdated',
                'lastUpdated',
            }:
                key = 'bgl_' + key
            glos.setInfo(key, value)
        ###
        for attr in (
            'defaultCharset',
            'sourceCharset',
            'targetCharset',
            'defaultEncoding',
            'sourceEncoding',
            'targetEncoding',
        ):
            value = getattr(self, attr, None)
            if value:
                glos.setInfo('bgl_' + attr, value)



    def isEndOfDictData(self):
        """
            Test for end of dictionary data.

            A bgl file stores dictionary data as a gzip compressed block.
            In other words, a bgl file stores a gzip data file inside.
            A gzip file consists of a series of "members".
            gzip data block in bgl consists of one member (I guess).
            Testing for block type returned by self.readBlock is not a reliable way to detect the end of gzip member.
            For example, consider 'Airport Code Dictionary.BGL' dictionary.
            To reliably test for end of gzip member block we must use a number of
            undocumented variables of gzip.GzipFile class.
            self.file._new_member - true if the current member has been completely read from the input file
            self.file.extrasize - size of buffered data
            self.file.offset - offset in the input file

            after reading one gzip member current position in the input file is set to the first byte after gzip data
            We may get this offset: self.file_bgl.tell()
            The last 4 bytes of gzip block contains the size of the original (uncompressed) input data modulo 2^32
        """
        return False

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def __del__(self):
        self.close()

    # returns False if error
    def readBlock(self, block):
        block.offset = self.file.tell()
        length = self.readBytes(1)
        if length==-1:
            log.debug('readBlock: length = -1')
            return False
        block.type = length & 0xf
        length >>= 4
        if length < 4:
            length = self.readBytes(length+1)
            if length == -1:
                log.error('readBlock: length = -1')
                return False
        else:
            length -= 4
        self.file.flush()
        if length > 0:
            try:
                block.data = self.file.read(length)
            except:
                ## struct.error: unpack requires a string argument of length 4, FIXME
                log.exception(
                    'failed to read block data: numBlocks=%s, length=%s, filePos=%s'%(
                        self.numBlocks,
                        length,
                        self.file.tell(),
                    )
                )
                block.data = b''
                return False
        else:
            block.data = b''
        return True

    def readBytes(self, num):
        """
            return -1 if error
        """
        if num<1 or num>4:
            log.error('invalid argument num=%s'%num)])
            return -1
        self.file.flush()
        buf = self.file.read(num)
        if len(buf)==0:
            log.debug('readBytes: end of file: len(buf)==0')
            return -1
        if len(buf) != num:
            log.error('readBytes: expected to read %s bytes, but found %s bytes'%(num, len(buf)))
            return -1
        return binStrToInt(buf)

    def readType0(self, block):
        code = block.data[0]
        if code==2:
            # this number is vary close to self.bglNumEntries, but does not always equal to the number of entries
            # see self.readType3, code == 12 as well
            num = binStrToInt(block.data[1:])
        elif code==8:
            self.defaultCharset = charsetInfoDecode(block.data[1:])
            if not self.defaultCharset:
                log.warning('defaultCharset is not valid')
        else:
            self.unknownBlock(block)
            return False
        return True

    def readType2(self, block, pass_num):
        """
            Process type 2 block

            Type 2 block is an embedded file (mostly Image or HTML).
            pass_num - pass number, may be 1 or 2
            On the first pass self.sourceEncoding is not defined and we cannot decode file names.
            That is why the second pass is needed. The second pass is costly, it
            apparently increases total processing time. We should avoid the second pass if possible.
            Most of the dictionaries do not have valuable resources, and those that do, use
            file names consisting only of ASCII characters. We may process these resources
            on the second pass. If all files have been processed on the first pass,
            the second pass is not needed.

            All dictionaries I've processed so far use only ASCII chars in file names.
            Babylon glossary builder replaces names of files, like links to images,
            with what looks like a hash code of the file name, for example "8FFC5C68.png".

            Return value: True if the resource was successfully processed,
                False - second pass is needed.
        """
        ## Embedded File (mostly Image or HTML)
        name = '' ## Embedded file name
        cont = '' ## Embedded file content
        pos = 0
        ## name:
        Len = block.data[pos]
        pos+=1
        if pos+Len > len(block.data):
            log.warning('reading block type 2: name too long')
            return True
        name += toStr(block.data[pos:pos+Len])
        pos += Len
        if name in ('C2EEF3F6.html', '8EAF66FD.bmp'):
            if pass_num == 1:
                log.info('Skipping non-useful file "%s"'%name)
            return True
        if isASCII(name):
            if pass_num > 1:
                return True # processed on the first pass
            # else decoding is not needed
        else:
            if pass_num == 1:
                return False # cannot process now, sourceEncoding is undefined
            #else:
            #    name = self.toUtf8(name, self.sourceEncoding)
        with open(join(self.resPath, name), 'wb') as resFile:
            resFile.write(block.data[pos:])
        self.resFiles.append(name)
        return True

    def readType3(self, block):
        keyCode, valueBytes = binStrToInt(block.data[:2]), block.data[2:]
        
        try:
            key = infoKeysByCode[keyCode]
        except KeyError:
            log.debug('Unknown info type keyCode=%s, block.type=%s, len(block.data)=%s'%(keyCode, block.type, len(block.data)))
            #open('%s-block.%s.%s'%(self.numBlocks, x, block.type), 'w').write(block.data)
            return False

        try:
            func = infoKeyDecodeMethods[key]
        except KeyError:
            value = valueBytes
        else:
            value = func(valueBytes)
            if value is None:
                log.warning('decode func for info key %s (%x) returned None'%(key, keyCode))

        if value:
            if isinstance(value, dict):
                self.info.update(value)
            else:
                self.info[key] = value

        return True


    def detectEncoding(self):
        """
            assign self.sourceEncoding and self.targetEncoding
        """
        utf8Encoding = self.info.get('utf8Encoding', False)
        
        if self.sourceEncodingOverwrite:
            self.sourceEncoding = self.sourceEncodingOverwrite
        elif utf8Encoding:
            self.sourceEncoding = 'utf8'
        elif self.sourceCharset:
            self.sourceEncoding = self.sourceCharset
        elif self.sourceLang:
            self.sourceEncoding = self.sourceLang.encoding
        else:
            self.sourceEncoding = 'cp1252'

        if self.targetEncodingOverwrite:
            self.targetEncoding = self.targetEncodingOverwrite
        elif utf8Encoding:
            self.targetEncoding = 'utf8'
        elif self.targetCharset:
            self.targetEncoding = self.targetCharset
        elif self.targetLang:
            self.targetEncoding = self.targetLang.encoding
        else:
            self.targetEncoding = 'cp1252'

        # not used
        if self.defaultEncodingOverwrite:
            self.defaultEncoding = self.defaultEncodingOverwrite
        elif self.defaultCharset:
            self.defaultEncoding = self.defaultCharset
        else:
            self.defaultEncoding = 'cp1252'

    def unknownBlock(self, block):
        log.debug('Unkown Block: type=%s, data_length=%s, number=%s'%(
            block.type,
            len(block.data),
            self.numBlocks,
        ))

    # return True if an entry has been read
    def readEntry(self):
        if not self.file:
            raise StopIteration
        block = Block()
        while not self.isEndOfDictData():
            if not self.readBlock(block):
                break
            if block.data and block.type in (1, 7, 10, 11, 13):
                pos = 0
                ## word:
                succeed, pos, word, raw_key = self.readEntryWord(block, pos)
                if not succeed:
                    continue
                ## defi:
                succeed, pos, defi, key_defi = self.readEntryDefi(block, pos, raw_key)
                if not succeed:
                    continue
                # now pos points to the first char after definition
                succeed, pos, alts = self.readEntryAlts(block, pos, raw_key, word)
                if not succeed:
                    continue

                return (
                    [word] + alts,
                    defi,
                )

        raise StopIteration

    def __iter__(self):
        return self

    def __next__(self):
        words, defis = self.readEntry()
        return Entry(words, defis)

    def readEntryWord(self, block, pos):
        """
            Read word part of entry.

            Return value is a list.
            (False, None, None, None) if error
            (True, pos, word, raw_key) if OK
        """
        Err = (False, None, None, None)
        if block.type == 11:
            if pos + 5 > len(block.data):
                log.error('reading block offset=%#x:: reading word size: pos + 5 > len(block.data)'%block.offset)
                return Err
            Len = binStrToInt(block.data[pos:pos+5])
            pos += 5
        else:
            if pos + 1 > len(block.data):
                log.error('reading block offset=%#x:: reading word size: pos + 1 > len(block.data)'%block.offset)
                return Err
            Len = block.data[pos]
            pos += 1
        if pos + Len > len(block.data):
            log.error('reading block offset=%#x:: reading word: pos + Len > len(block.data)'%block.offset)
            return Err
        raw_key = block.data[pos:pos+Len]
        word = self.processKey(raw_key)
        """
            Entry keys may contain html text, for example,
            ante<font face'Lucida Sans Unicode'>&lt; meridiem
            arm und reich c=t&gt;2003;</charset></font>und<font face='Lucida Sans Unicode'>
            etc.
            Babylon does not process keys as html, it display them as is.
            Html in keys is the problem of that particular dictionary.
            We should not process keys as html, since Babylon do not process them as such.
        """
        pos += Len
        self.wordLenMax = max(self.wordLenMax, len(word))
        return True, pos, word, raw_key

    def readEntryDefi(self, block, pos, raw_key):
        Err = (False, None, None, None)
        if block.type == 11:
            if pos + 8 > len(block.data):
                log.error('reading block offset=%#x:: reading defi size: pos + 8 > len(block.data)'%block.offset)
                return Err
            pos += 4 # binStrToInt(block.data[pos:pos+4]) - may be 0, 1
            Len = binStrToInt(block.data[pos:pos+4])
            pos += 4
        else:
            if pos + 2 > len(block.data):
                log.error('reading block offset=%#x:: reading defi size: pos + 2 > len(block.data)'block.offset)
                return Err
            Len = binStrToInt(block.data[pos:pos+2])
            pos += 2
        if pos + Len > len(block.data):
            log.error('reading block offset=%#x:: reading defi: pos + Len > len(block.data)'%block.offset)
            return Err
        raw_defi = block.data[pos:pos+Len]
        defi = self.processDefi(raw_defi, raw_key)
        self.defiLenMax = max(self.defiLenMax, len(raw_defi))

        pos += Len
        return True, pos, defi, raw_defi

    def readEntryAlts(self, block, pos, raw_key, key):
        """
            returns:
                (False, None, None) if error
                (True, pos, alts) if succeed
        
        """
        Err = (False, None, None)
        # use set instead of list to prevent duplicates
        alts = set()
        while pos < len(block.data):
            if block.type == 11:
                if pos + 4 > len(block.data):
                    log.error('reading block offset=%#x:: reading alt size: pos + 4 > len(block.data)'%block.offset)
                    return Err
                Len = binStrToInt(block.data[pos:pos+4])
                pos += 4
                if Len == 0:
                    if pos + Len != len(block.data):
                        # no evidence
                        log.warning('reading block offset=%#x:: reading alt size: pos + Len != len(block.data)'%block.offset)
                    break
            else:
                if pos + 1 > len(block.data):
                    log.error('reading block offset=%#x:: reading alt size: pos + 1 > len(block.data)'%block.offset)
                    return Err
                Len = block.data[pos]
                pos += 1
            if pos + Len > len(block.data):
                log.error('reading block offset=%#x:: reading alt: pos + Len > len(block.data)'%block.offset)
                return Err
            raw_alt = block.data[pos:pos+Len]
            alt = self.processAlternativeKey(raw_alt, raw_key)
            # Like entry key, alt is not processed as html by babylon, so do we.
            alts.add(alt)
            pos += Len
        if key in alts:
            alts.remove(key)
        return True, pos, list(sorted(alts))


    def charReferencesStat(self, text, encoding):
        pass


    def decodeCharsetTags(self, text, defaultEncoding):
        """
            Decode html text taking into account charset tags and default encoding.

            Return value: (u_text, defaultEncodingOnly)
            u_text is str
            defaultEncodingOnly parameter is false if the text contains parts encoded with
            non-default encoding (babylon character references '<CHARSET c="T">00E6;</CHARSET>'
            do not count).
        """
        parts = re.split(charsetDecodePattern, text)
        u_text = ''
        encodings = [] # stack of encodings
        defaultEncodingOnly = True
        for i, part in enumerate(parts):
            if i % 3 == 0: # text block
                encoding = encodings[-1] if encodings else defaultEncoding
                text2 = part
                if encoding == 'babylon-reference':
                    refs = text2.split(';')
                    for j, ref in enumerate(refs):
                        ref = refs[j]
                        if not ref:
                            if j != len(refs)-1:
                                log.debug(
                                    'decoding charset tags, text=%s\n'%text
                                    'blank <charset c=t> character reference (%s)\n'%text2
                                )
                            continue
                        if not re.match('^[0-9a-fA-F]{4}$', ref):
                            log.debug(
                                'decoding charset tags, text=%s\n'%text
                                'invalid <charset c=t> character reference (%s)\n'%(, text2)
                            )
                            continue
                        code = int(ref, 16)
                        u_text += chr(code)
                else:
                    self.charReferencesStat(text2, encoding)
                    if encoding == 'cp1252':
                        text2 = replace_ascii_char_refs(text2, encoding)
                    if self.strictStringConvertion:
                        try:
                            u_text2 = text2.decode(encoding)
                        except UnicodeError:
                            log.debug(
                                'decoding charset tags, text=%s\n'%text
                                'fragment(%s)\n'%text2
                                'conversion error:\n%s'%excMessage()
                            )
                            u_text2 = text2.decode(encoding, 'replace')
                    else:
                        u_text2 = text2.decode(encoding, 'replace')
                    u_text += u_text2
                    if encoding != defaultEncoding:
                        defaultEncodingOnly = False
            elif i % 3 == 1: # <charset...> or </charset>
                if part.startswith('</'):
                    # </charset>
                    if encodings:
                        encodings.pop()
                    else:
                        log.debug(
                            'decoding charset tags, text=%s\n'%text
                            'unbalanced </charset> tag\n'
                        )
                else:
                    # <charset c="?">
                    c = parts[i+1].lower()
                    if c == 't':
                        encodings.append('babylon-reference')
                    elif c == 'u':
                        encodings.append('utf-8')
                    elif c == 'k':
                        encodings.append(self.sourceEncoding)
                    elif c == 'e':
                        encodings.append(self.sourceEncoding)
                    elif c == 'g':
                        # gbk or gb18030 encoding (not enough data to make distinction)
                        encodings.append('gbk')
                    else:
                        log.debug(
                            'decoding charset tags, text=%s\n'%text
                            'unknown charset code = %s\n'%c
                        )
                        # add any encoding to prevent 'unbalanced </charset> tag' error
                        encodings.append(defaultEncoding)
            else:
                # c attribute of charset tag if the previous tag was charset
                pass
        if encodings:
            log.debug(
                'decoding charset tags, text=%s\n'%text
                'unclosed <charset...> tag\n'
            )
        return u_text, defaultEncodingOnly


    def processKey(self, word):
        """
            word is a bytes instance
            Return entry key in utf-8 encoding
        """
        main_word, strip_cnt = stripDollarIndexes(word)
        if strip_cnt > 1:
            log.debug('processKey(%s):\nnumber of dollar indexes = %s'%(word, strip_cnt))
        # convert to unicode
        if self.strictStringConvertion:
            try:
                u_main_word = main_word.decode(self.sourceEncoding)
            except UnicodeError:
                log.debug(
                    'processKey(%s):\nconversion error:\n%s'%(word, excMessage())
                )
                u_main_word = main_word.decode(self.sourceEncoding, 'ignore')
        else:
            u_main_word = main_word.decode(self.sourceEncoding, 'ignore')

        if self.processHtmlInKey:
            #u_main_word_orig = u_main_word
            u_main_word = strip_html_tags(u_main_word)
            u_main_word = replace_html_entries_in_keys(u_main_word)
            #if(re.match('.*[&<>].*', u_main_word_orig)):
                #log.debug('original text: ' + u_main_word_orig + '\n' \
                        #+ 'new      text: ' + u_main_word + '\n')
        u_main_word = remove_control_chars(u_main_word)
        u_main_word = replace_new_lines(u_main_word)
        u_main_word = u_main_word.lstrip()
        u_main_word = u_main_word.rstrip(self.keyRStripChars)
        return u_main_word

    def processAlternativeKey(self, raw_word, raw_key):
        main_word, strip_cnt = stripDollarIndexes(raw_word)
        # convert to unicode
        if self.strictStringConvertion:
            try:
                u_main_word = main_word.decode(self.sourceEncoding)
            except UnicodeError:
                log.debug(
                    'processAlternativeKey(%s)\nkey = %s:\nconversion error:\n%s'%(raw_word, raw_key, excMessage())
                )
                u_main_word = main_word.decode(self.sourceEncoding, 'ignore')
        else:
            u_main_word = main_word.decode(self.sourceEncoding, 'ignore')

        # strip '/' before words
        u_main_word = re.sub(self.stripSlashAltKeyPattern, r'\1\2', u_main_word)

        if self.processHtmlInKey:
            #u_main_word_orig = u_main_word
            u_main_word = strip_html_tags(u_main_word)
            u_main_word = replace_html_entries_in_keys(u_main_word)
            #if(re.match('.*[&<>].*', u_main_word_orig)):
                #log.debug('original text: ' + u_main_word_orig + '\n' \
                        #+ 'new      text: ' + u_main_word + '\n')
        u_main_word = remove_control_chars(u_main_word)
        u_main_word = replace_new_lines(u_main_word)
        u_main_word = u_main_word.lstrip()
        u_main_word = u_main_word.rstrip(self.keyRStripChars)
        return u_main_word





    def processDefi(self, defi, raw_key):
        fields = DefinitionFields()
        self.collectDefiFields(defi, raw_key, fields)


        fields.u_defi, fields.singleEncoding = self.decodeCharsetTags(fields.defi, self.targetEncoding)
        if fields.singleEncoding:
            fields.encoding = self.targetEncoding
        fields.u_defi = fixImgLinks(fields.u_defi)
        fields.u_defi = replace_html_entries(fields.u_defi)
        fields.u_defi = remove_control_chars(fields.u_defi)
        fields.u_defi = normalize_new_lines(fields.u_defi)
        fields.u_defi = fields.u_defi.strip()

        if fields.title:
            fields.u_title, singleEncoding = self.decodeCharsetTags(fields.title, self.sourceEncoding)
            fields.u_title = replace_html_entries(fields.u_title)
            fields.u_title = remove_control_chars(fields.u_title)

        if fields.title_trans:
            # sourceEncoding or targetEncoding ?
            fields.u_title_trans, singleEncoding = self.decodeCharsetTags(
                fields.title_trans,
                self.sourceEncoding,
            )
            fields.u_title_trans = replace_html_entries(fields.u_title_trans)
            fields.u_title_trans = remove_control_chars(fields.u_title_trans)

        if fields.transcription_50:
            if fields.transcription_50_code == 0x10:
                # contains values like this (char codes):
                # 00 18 00 19 00 1A 00 1B 00 1C 00 1D 00 1E 00 40 00 07
                # this is not utf-16
                # what is this?
                pass
            elif fields.transcription_50_code == 0x1b:
                fields.u_transcription_50, singleEncoding = self.decodeCharsetTags(
                    fields.transcription_50,
                    self.sourceEncoding,
                )
                fields.u_transcription_50 = replace_html_entries(fields.u_transcription_50)
                fields.u_transcription_50 = remove_control_chars(fields.u_transcription_50)
            elif fields.transcription_50_code == 0x18:
                # incomplete text like:
                # t c=T>02D0;</charset>g<charset c=T>0259;</charset>-
                # This defi normally contains fields.transcription_60 in this case.
                pass
            else:
                log.debug('processDefi(%s)\n'
                    'key = (%s):\ndefi field 50, unknown code: 0x{2:x}'%(
                        defi,
                        raw_key,
                        fields.transcription_50_code,
                    ))

        if fields.transcription_60:
            if fields.transcription_60_code == 0x1b:
                fields.u_transcription_60, singleEncoding = self.decodeCharsetTags(
                    fields.transcription_60,
                    self.sourceEncoding,
                )
                fields.u_transcription_60 = replace_html_entries(fields.u_transcription_60)
                fields.u_transcription_60 = remove_control_chars(fields.u_transcription_60)
                fields.u_transcription_60 = fields.u_transcription_60.decode('utf-8')
            else:
                log.debug('processDefi(%s)\n'
                    'key = (%s):\ndefi field 60, unknown code: 0x{2:x}'%(
                        defi,
                        raw_key,
                        fields.transcription_60_code,
                    ))

        if fields.field_1a:
            fields.u_field_1a, singleEncoding = self.decodeCharsetTags(
                fields.field_1a,
                self.sourceEncoding,
            )

        self.processDefiStat(fields, defi, raw_key)

        defi_format = ''
        if fields.partOfSpeech or fields.u_title:
            if fields.partOfSpeech:
                defi_format += '<font color="#%s">%s</font>'%(
                    self.partOfSpeechColor,
                    xml_escape(fields.partOfSpeech),
                )
            if fields.u_title:
                if defi_format:
                    defi_format += ' '
                defi_format += fields.u_title
            defi_format += '<br>\n'
        if fields.u_title_trans:
            defi_format += fields.u_title_trans + '<br>\n'
        if fields.u_transcription_50:
            defi_format += '[%s]<br>\n'%(fields.u_transcription_50)
        if fields.u_transcription_60:
            defi_format += '[%s]<br>\n'%(fields.u_transcription_60)
        if fields.u_defi:
            defi_format += fields.u_defi
        return defi_format

    def processDefiStat(self, fields, defi, raw_key):
        pass

    def findDefiFieldsStart(self, defi):
        """
            Find the beginning of the definition trailing fields.

            Return value is the index of the first chars of the field set,
            or -1 if the field set is not found.

            Normally '\x14' should signal the beginning of the definition fields,
            but some articles may contain this characters inside, so we get false match.
            As a workaround we may check the following chars. If '\x14' is followed
            by space, we assume this is part of the article and continue search.
            Unfortunately this does no help in many cases...
        """
        if self.noControlSequenceInDefi:
            return -1
        index = -1
        while True:
            index = defi.find(b'\x14', index+1, -1)## -1: not the last character
            if index == -1:
                break
            if defi[index+1] != b' ':
                break
        return index

    def collectDefiFields(self, defi, raw_key, fields):
        """
            d0 - index of the '\x14 char in defi
            d0 may be the last char of the string
            entry definition structure:
            <main definition>['\x14'[<one char - field code><field data, arbitrary length>]*]
        """
        d0 = self.findDefiFieldsStart(defi)
        if d0 == -1:
            fields.defi = defi
            return
        
        fields.defi = defi[:d0]

        i = d0 + 1
        while i < len(defi):
            if self.metadata2:
                self.metadata2.defiTrailingFields[defi[i]] += 1

            if defi[i] == '\x02': # part of speech # '\x02' <one char - part of speech>
                if fields.partOfSpeech:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nduplicate part of speech item'%raw_key
                    )
                if i+1 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ndefi ends after \\x02'%raw_key
                    )
                    return
                posCode = defi[i+1]
                
                try:
                    fields.partOfSpeech = partOfSpeechByCode[posCode]
                except KeyError:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\n'%raw_key
                        'unknown part of speech. Char code = %#x'%posCode
                    )
                    return
                i += 2
            elif defi[i] == '\x06': # \x06<one byte>
                if fields.field_06:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nduplicate type 6'%raw_key
                    )
                if i+1 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ndefi ends after \\x06'%raw_key
                    )
                    return
                fields.field_06 = defi[i+1]
                i += 2
            elif defi[i] == '\x07': # \x07<two bytes>
                # Found in 4 Hebrew dictionaries. I do not understand.
                if i+3 > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x07'%raw_key
                    )
                    return
                fields.field_07 = defi[i+1:i+3]
                i += 3
            elif defi[i] == '\x13': # '\x13'<one byte - length><data>
                # known values:
                # 03 06 0D C7
                # 04 00 00 00 44
                # ...
                # 04 00 00 00 5F
                if i + 1 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x13'%raw_key
                    )
                    return
                Len = defi[i+1]
                i += 2
                if Len == 0:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nblank data after \\x13'%raw_key
                    )
                    continue
                if i+Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x13'%raw_key
                    )
                    return
                fields.field_13 = defi[i:i+Len]
                i += Len
            elif defi[i] == '\x18': # \x18<one byte - title length><entry title>
                if fields.title:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nduplicate entry title item'%raw_key
                    )
                if i+1 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ndefi ends after \\x18'%raw_key
                    )
                    return
                i += 1
                Len = defi[i]
                i += 1
                if Len == 0:
                    #log.debug(
                    #    'collecting definition fields, defi = %s\n'%defi
                    #    'key = (%s):\nblank entry title'%raw_key
                    #)
                    continue
                if i + Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntitle is too long'%raw_key
                    )
                    return
                fields.title = defi[i:i+Len]
                i += Len
            elif defi[i] == '\x1A': # '\x1A'<one byte - length><text>
                # found only in Hebrew dictionaries, I do not understand.
                if i + 1 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x1A'%raw_key
                    )
                    return
                Len = defi[i+1]
                i += 2
                if Len == 0:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nblank data after \\x1A'%raw_key
                    )
                    continue
                if i+Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x1A'%raw_key
                    )
                    return
                fields.field_1a = defi[i:i+Len]
                i += Len
            elif defi[i] == '\x28': # '\x28' <two bytes - length><html text>
                # title with transcription?
                if i + 2 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x28'%raw_key
                    )
                    return
                i += 1
                Len = binStrToInt(defi[i:i+2])
                i += 2
                if Len == 0:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nblank data after \\x28'%raw_key
                    )
                    continue
                if i+Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x28'%raw_key
                    )
                    return
                fields.title_trans = defi[i:i+Len]
                i += Len
            elif 0x40 <= defi[i] <= 0x4f: # [\x41-\x4f] <one byte> <text>
                # often contains digits as text:
                # 56
                # &#0230;lps - key Alps
                # 48@i
                # has no apparent influence on the article
                code = defi[i]
                Len = defi[i] - 0x3f
                if i+2+Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x40+'%raw_key
                    )
                    return
                i += 2
                text = defi[i:i+Len]
                i += Len
                log.debug('\nunknown defi trailing field %#x: %s'%(code, text))
            elif defi[i] == '\x50': # \x50 <one byte> <one byte - length><data>
                if i + 2 >= len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x50'%raw_key
                    )
                    return
                fields.transcription_50_code = defi[i+1]
                Len = defi[i+2]
                i += 3
                if Len == 0:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nblank data after \\x50'%raw_key
                    )
                    continue
                if i+Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x50'%raw_key
                    )
                    return
                fields.transcription_50 = defi[i:i+Len]
                i += Len
            elif defi[i] == '\x60': # '\x60' <one byte> <two bytes - length> <text>
                if i + 4 > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x60'%raw_key
                    )
                    return
                fields.transcription_60_code = defi[i+1]
                i += 2
                Len = binStrToInt(defi[i:i+2])
                i += 2
                if Len == 0:
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\nblank data after \\x60'%raw_key
                    )
                    continue
                if i+Len > len(defi):
                    log.debug(
                        'collecting definition fields, defi = %s\n'%defi
                        'key = (%s):\ntoo few data after \\x60'%raw_key
                    )
                    return
                fields.transcription_60 = defi[i:i+Len]
                i += Len
            else:
                log.debug(
                    'collecting definition fields, defi = %s\n'%defi
                    'key = (%s):\n'%raw_key
                    'unknown control char. Char code = {2:#X}'%defi[i]
                )
                return




