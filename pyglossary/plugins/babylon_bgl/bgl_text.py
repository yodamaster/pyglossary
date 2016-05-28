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

entryPattern = re.compile('(?:&#x|&#|&)(\\w+);?', re.I)
entryKeyPattern = re.compile('(?:&#x|&#|&)(\\w+);', re.I)


def replace_html_entry_no_escape(m):
    """
        Replace character entity with the corresponding character

        Return the original string if conversion fails.
        Use this as a replace function of re.sub.
    """
    import html.entities
    from pyglossary.html_utils import name2codepoint

    text = m.group(0)
    name = m.group(1)
    res = None
    if text[:2] == '&#':
        # character reference
        try:
            if text[:3].lower() == '&#x':
                code = int(name, 16)
            else:
                code = int(name)
            if code <= 0:
                raise ValueError()
            res = chr(code)
        except (ValueError, OverflowError):
            res = chr(0xFFFD) # replacement character
    elif text[0] == '&':
        # named entity
        try:
            res = chr(html.entities.name2codepoint[name])
        except KeyError:
            try:
                res = chr(name2codepoint[name.lower()])
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
                log.warning('unknown html entity %s'%text)
                res = text
    else:
        raise ArgumentError()
    return res

def replace_html_entry(m):
    """
        Same as replace_html_entry_no_escape, but escapes result string

        Only <, >, & characters are escaped.
    """
    res = replace_html_entry_no_escape(m)
    if m.group(0) == res: # conversion failed
        return res
    else:
        return xml_escape(res)


def replace_html_entries(text):
    # &ldash;
    # &#0147;
    # &#x010b;
    return re.sub(entryPattern, replace_html_entry, text)

def replace_html_entries_in_keys(text):
    # &ldash;
    # &#0147;
    # &#x010b;
    return re.sub(entryKeyPattern, replace_html_entry_no_escape, text)



def replace_dingbat(m):
    """
        replace chars \\u008c-\\u0095 with \\u2776-\\u277f
    """
    ch = m.group(0)
    code = ch + (0x2776-0x8c)
    return chr(code)

def new_line_escape_string_callback(m):
    ch = m.group(0)
    if ch == '\n':
        return '\\n'
    if ch == '\r':
        return '\\r'
    if ch == '\\':
        return '\\\\'
    return ch

def new_line_escape_string(text):
    """
        convert text to c-escaped string:
        \ -> \\
        new line -> \n or \r
    """
    return re.sub('[\\r\\n\\\\]', new_line_escape_string_callback, text)


def strip_html_tags(text):
    return re.sub('(?:<[/a-zA-Z].*?(?:>|$))+', ' ', text)



def remove_control_chars(text):
    # \x09 - tab
    # \x0a - line feed
    # \x0b - vertical tab
    # \x0d - carriage return
    return re.sub('[\x00-\x08\x0c\x0e-\x1f]', '', text)

def replace_new_lines(text):
    return re.sub('[\r\n]+', ' ', text)

def normalize_new_lines(text):
    """
        convert new lines to unix style and remove consecutive new lines
    """
    return re.sub('[\r\n]+', '\n', text)


def replace_ascii_char_refs(text, encoding):
    # &#0147;
    # &#x010b;
    pat = re.compile('(&#\\w+;)', re.I)
    parts = re.split(pat, text)
    for i in range(len(parts)):
        if i % 2 != 1:
            continue
        # reference
        text2 = parts[i]
        try:
            if text2[:3].lower() == '&#x':
                code = int(text2[3:-1], 16)
            else:
                code = int(text2[2:-1])
            if code <= 0:
                raise ValueError()
        except (ValueError, OverflowError):
            code = -1
        if code < 128 or code > 255:
            continue
        # no need to escape '<', '>', '&'
        parts[i] = chr(code)
    return ''.join(parts)


def fixImgLinks(text):
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
    return text.replace('\x1e', '').replace('\x1f', '')




def stripDollarIndexes(word):
    i = 0
    main_word = b''
    strip_cnt = 0 # number of sequences found
    # strip $<index>$ sequences
    while True:
        d0 = word.find(b'$', i)
        if d0 == -1:
            main_word += word[i:]
            break
        d1 = word.find(b'$', d0+1)
        if d1 == -1:
            #log.debug('stripDollarIndexes(%s):\npaired $ is not found'%word)
            main_word += word[i:]
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
            #log.debug('stripDollarIndexes(%s):\nfound $$'%word)
            main_word += word[i:d0]
            i = d1 + 1
            while i < len(word) and word[i] == ord(b'$'):
                i += 1
            if i >= len(word):
                break
            continue
        ok = True
        for x in word[d0+1:d1]:
            if x not in b'0123456789':
                #log.debug('stripDollarIndexes(%s):\nnon-digit between $$'%word)
                ok = False
                break
        if not ok:
            main_word += word[i:d1]
            i = d1
            continue
        if d1+1 < len(word) and word[d1+1] != ' ':
            """
                Examples:
                make do$4$/make /do
                potere$1$<BR><BR>See also <a href='file://ITAL-ENG POTERE 1249-1250.pdf'>notes...</A>
                volere$1$<BR><BR>See also <a href='file://ITAL-ENG VOLERE 1469-1470.pdf'>notes...</A>
                Ihre$1$Ihres
            """
            #log.debug('stripDollarIndexes(%s):\nsecond $ is followed by non-space'%word))
            pass
        main_word += word[i:d0]
        i = d1+1
        strip_cnt += 1

    return main_word, strip_cnt











