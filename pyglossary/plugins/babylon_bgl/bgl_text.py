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

import re
from pyglossary.plugins.formats_common import log
from pyglossary.xml_utils import xml_escape


entryPattern = re.compile('(?:&#x|&#|&)(\\w+);?', re.I)
entryKeyPattern = re.compile('(?:&#x|&#|&)(\\w+);', re.I)
asciiCharRefPattern = re.compile(b'(&#\\w+;)', re.I)

unkownHtmlEntries = set()

def replace_html_entry_no_escape(u_matched):
    """
        u_matched: instance of _sre.SRE_Match
        Replace character entity with the corresponding character

        Return the original string if conversion fails.
        Use this as a replace function of re.sub.
    """
    import html.entities
    from pyglossary.html_utils import name2codepoint

    u_text = u_matched.group(0)
    u_name = u_matched.group(1)
    if log.isDebug(): assert isinstance(u_text, str) and isinstance(u_name, str)

    u_res = None
    if u_text[:2] == '&#':
        # character reference
        try:
            if u_text[:3].lower() == '&#x':
                code = int(u_name, 16)
            else:
                code = int(u_name)
            if code <= 0:
                raise ValueError()
            u_res = chr(code)
        except (ValueError, OverflowError):
            u_res = chr(0xFFFD) # replacement character
    elif u_text[0] == '&':
        # named entity
        try:
            u_res = chr(html.entities.name2codepoint[u_name])
        except KeyError:
            try:
                u_res = chr(name2codepoint[u_name.lower()])
            except KeyError:
                """
                    Babylon dictionaries contain a lot of non-standard entity references,
                    for example, csdot, fllig, nsm, cancer, thlig, tsdot, upslur...
                    This not just a typo. These entries repeat over and over again.
                    Perhaps they had meaning in the source dictionary that was converted to Babylon,
                    but now the meaning is lost. Babylon does render them as is, that is, for example,
                    &csdot; despite other references like &amp; are replaced with corresponding
                    characters.
                """
                if not u_text in unkownHtmlEntries:
                    log.warning('unknown html entity %s'%u_text)
                    unkownHtmlEntries.add(u_text)
                u_res = u_text
    else:
        raise ArgumentError()
    return u_res

def replace_html_entry(u_matched):
    """
        u_matched: instance of _sre.SRE_Match
        Same as replace_html_entry_no_escape, but escapes result string

        Only <, >, & characters are escaped.
    """
    u_res = replace_html_entry_no_escape(u_matched)
    if u_matched.group(0) == u_res: # conversion failed
        return u_res
    else:
        return xml_escape(u_res)


def replace_dingbat(matched):
    """
        matched: instance of _sre.SRE_Match
        replace chars \\u008c-\\u0095 with \\u2776-\\u277f
    """
    ch = matched.group(0)
    code = ch + (0x2776-0x8c)
    return chr(code)

def new_line_escape_string_callback(matched):
    """
        matched: instance of _sre.SRE_Match
    """
    ch = matched.group(0)
    if ch == '\n':
        return '\\n'
    if ch == '\r':
        return '\\r'
    if ch == '\\':
        return '\\\\'
    return ch


def replace_html_entries(u_text):
    # &ldash;
    # &#0147;
    # &#x010b;
    if log.isDebug(): assert isinstance(u_text, str)
    return re.sub(
        entryPattern,
        replace_html_entry,
        u_text,
    )

def replace_html_entries_in_keys(u_text):
    # &ldash;
    # &#0147;
    # &#x010b;
    if log.isDebug(): assert isinstance(u_text, str)
    return re.sub(
        entryKeyPattern,
        replace_html_entry_no_escape,
        u_text,
    )




def new_line_escape_string(u_text):
    """
        convert text to c-escaped string:
        \ -> \\
        new line -> \n or \r
    """
    if log.isDebug(): assert isinstance(u_text, str)
    return re.sub(
        '[\\r\\n\\\\]',
        new_line_escape_string_callback,
        u_text,
    )


def strip_html_tags(u_text):
    if log.isDebug(): assert isinstance(text, str)
    return re.sub(
        '(?:<[/a-zA-Z].*?(?:>|$))+',
        ' ',
        u_text,
    )


def remove_control_chars(u_text):
    # \x09 - tab
    # \x0a - line feed
    # \x0b - vertical tab
    # \x0d - carriage return
    if log.isDebug(): assert isinstance(u_text, str)
    return re.sub(
        '[\x00-\x08\x0c\x0e-\x1f]',
        '',
        u_text,
    )


def replace_new_lines(u_text):
    if log.isDebug(): assert isinstance(u_text, str)
    return re.sub(
        '[\r\n]+',
        ' ',
        u_text,
    )


def normalize_new_lines(u_text):
    """
        convert new lines to unix style and remove consecutive new lines
    """
    if log.isDebug(): assert isinstance(u_text, str)
    return re.sub(
        '[\r\n]+',
        '\n',
        u_text,
    )


def replace_ascii_char_refs(b_text, encoding):
    # &#0147;
    # &#x010b;
    if log.isDebug(): assert isinstance(b_text, bytes)
    b_parts = re.split(asciiCharRefPattern, b_text)
    for i_part, b_part in enumerate(b_parts):
        if i_part % 2 != 1:
            continue
        # reference
        try:
            if b_part[:3].lower() == '&#x':
                code = int(b_part[3:-1], 16)
            else:
                code = int(b_part[2:-1])
            if code <= 0:
                raise ValueError()
        except (ValueError, OverflowError):
            code = -1
        if code < 128 or code > 255:
            continue
        # no need to escape '<', '>', '&'
        b_parts[i_part] = bytes([code])
    return b''.join(b_parts)


def fixImgLinks(u_text):
    """
        Fix img tag links

        src attribute value of image tag is often enclosed in \x1e - \x1f characters.
        For example, <IMG border='0' src='\x1e6B6C56EC.png\x1f' width='9' height='8'>.
        Naturally the control characters are not part of the image source name.
        They may be used to quickly find all names of resources.
        This function strips all such characters.
        Control characters \x1e and \x1f are useless in html text, so we may safely remove
        all of them, irrespective of context.
    """
    if log.isDebug(): assert isinstance(u_text, str)
    return u_text.replace('\x1e', '').replace('\x1f', '')




def stripDollarIndexes(b_word):
    if log.isDebug(): assert isinstance(b_word, bytes)
    i = 0
    b_word_main = b''
    strip_cnt = 0 # number of sequences found
    # strip $<index>$ sequences
    while True:
        d0 = b_word.find(b'$', i)
        if d0 == -1:
            b_word_main += b_word[i:]
            break
        d1 = b_word.find(b'$', d0+1)
        if d1 == -1:
            #log.debug('stripDollarIndexes(%s):\npaired $ is not found'%b_word)
            b_word_main += b_word[i:]
            break
        if d1 == d0+1:
            """
                You may find keys (or alternative keys) like these:
                sur l'arbre$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
                obscurantiste$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
                They all end on a sequence of '$', key length including dollars is always 60 chars.
                You may find keys like these:
                extremidade-$$$-$$$-linha
                .FIRM$$$$$$$$$$$$$
                etc

                summary: we must remove any sequence of dollar signs longer than 1 chars
            """
            #log.debug('stripDollarIndexes(%s):\nfound $$'%b_word)
            b_word_main += b_word[i:d0]
            i = d1 + 1
            while i < len(b_word) and b_word[i] == ord(b'$'):
                i += 1
            if i >= len(b_word):
                break
            continue
        ok = True
        for x in b_word[d0+1:d1]:
            if x not in b'0123456789':
                #log.debug('stripDollarIndexes(%s):\nnon-digit between $$'%b_word)
                ok = False
                break
        if not ok:
            b_word_main += b_word[i:d1]
            i = d1
            continue
        if d1+1 < len(b_word) and b_word[d1+1] != ' ':
            """
                Examples:
                make do$4$/make /do
                potere$1$<BR><BR>See also <a href='file://ITAL-ENG POTERE 1249-1250.pdf'>notes...</A>
                volere$1$<BR><BR>See also <a href='file://ITAL-ENG VOLERE 1469-1470.pdf'>notes...</A>
                Ihre$1$Ihres
            """
            #log.debug('stripDollarIndexes(%s):\nsecond $ is followed by non-space'%b_word))
            pass
        b_word_main += b_word[i:d0]
        i = d1+1
        strip_cnt += 1

    return b_word_main, strip_cnt











