# -*- coding: utf-8 -*-
## appledict/_dict.py
## Output to Apple Dictionary xml sources for Dictionary Development Kit.
##
## Copyright (C) 2012 Xiaoqiang Wang <xiaoqiangwang AT gmail DOT com>
##
## This program is a free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, version 3 of the License.
##
## You can get a copy of GNU General Public License along this program
## But you can always get it from http://www.gnu.org/licenses/gpl.txt
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License for more details.

import logging
log = logging.getLogger('root')

import re
import string
from xml.sax.saxutils import unescape, quoteattr

import xdxf

from . import _normalize

def dictionary_begin(glos, f, frontBackMatter):
    # write header
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<d:dictionary xmlns="http://www.w3.org/1999/xhtml" xmlns:d="http://www.apple.com/DTDs/DictionaryService-1.0.rng">\n')

    if frontBackMatter:
        with open(frontBackMatter, 'r') as front_back_matter:
            f.write(front_back_matter.read())

def get_beautiful_soup():
    try:
        import bs4 as BeautifulSoup
    except ImportError:
        try:
            import BeautifulSoup
        except ImportError:
            return None
    if int(BeautifulSoup.__version__.split('.')[0]) < 4:
        raise ImportError('BeautifulSoup is too old, required at least version 4, %r found.\n'
                          'please run `pip2 install beautifulsoup4`.' % BeautifulSoup.__version__)
    return BeautifulSoup

digs = string.digits + string.letters

def base36(x):
    """
    simplified version of int2base
    http://stackoverflow.com/questions/2267362/convert-integer-to-a-string-in-a-given-numeric-base-in-python#2267446
    """
    digits = []
    while x:
        digits.append(digs[x % 36])
        x /= 36
    digits.reverse()
    return ''.join(digits)

def id_generator():
    cnt = 1

    while True:
        s = '_%s' % base36(cnt)
        yield s
        cnt += 1

def indexes_generator(indexes_lang):
    """
    factory that acts according to glossary language

    :param indexes_lang: str
    """
    indexer = None
    """Callable[[Sequence[str], str], Sequence[str]]"""
    if indexes_lang:
        from . import indexes as idxs
        indexer = idxs.languages.get(indexes_lang, None)
        if not indexer:
            msg = "extended indexes not supported for the specified language: %s.\n"\
                  "following languages avaible: %s." %\
                  (indexes_lang, ', '.join(list(idxs.languages.keys())))
            from pyglossary.glossary import log
            log.error(msg)
            raise ValueError(msg)

    def generate_indexes(title, alts, content, BeautifulSoup):
        indexes = [title]
        indexes.extend(alts)

        if BeautifulSoup:
            quoted_title = BeautifulSoup.dammit.EntitySubstitution.substitute_xml(title, True)
        else:
            quoted_title = '"%s"' % title.replace('>', '&gt;').replace('"', "&quot;")

        if indexer:
            indexes = set(indexer(indexes, content))

        normal_indexes = set()
        for idx in indexes:
            normal = _normalize.title(idx, BeautifulSoup)
            normal_indexes.add(_normalize.title_long(normal))
            normal_indexes.add(_normalize.title_short(normal))
        normal_indexes.discard(title)

        normal_indexes = [s for s in normal_indexes if s.strip()]
        # skip empty titles.  everything could happen.

        s = '<d:index d:value=%s d:title=%s/>' % (quoted_title, quoted_title)
        if BeautifulSoup:
            for idx in normal_indexes:
                s += '<d:index d:value=%s d:title=%s/>' % (
                    BeautifulSoup.dammit.EntitySubstitution.substitute_xml(idx, True),
                    quoted_title)
        else:
            for idx in normal_indexes:
                s += '<d:index d:value="%s" d:title=%s/>' % (
                    idx.replace('>', '&gt;').replace('"', "&quot;"),
                    quoted_title)
        return s
    return generate_indexes


close_tag = re.compile('<(BR|HR)>', re.IGNORECASE)
nonprintable = re.compile('[\x00-\x07\x0e-\x1f]')
img_tag = re.compile('<IMG (.*?)>', re.IGNORECASE)

em0_9_re = re.compile(r'<div style="margin-left:(\d)em">')
em0_9_sub = r'<div class="m\1">'

em0_9_ex_re = re.compile(r'<div class="ex" style="margin-left:(\d)em;color:steelblue">')
em0_9_ex_sub = r'<div class="m\1 ex">'

href_re = re.compile(r'''href=(["'])(.*?)\1''')
href_sub = (lambda x:
            x.group()
            if x.groups()[1].startswith('http') else
            'href=%s' % quoteattr('x-dictionary:d:' +
                                  unescape(x.groups()[1], {'&quot;': '"'})))

is_green = lambda x: 'color:green' in x.get('style', '')
margin_re = re.compile('margin-left:(\d)em')


def remove_style(tag, line):
    s = ''.join(tag['style'].replace(line, '').split(';'))
    if s:
        tag['style'] = s
    else:
        del tag['style']


def format_clean_content(title, body, BeautifulSoup):
    # heavily integrated with output of dsl reader plugin!
    # and with xdxf also.
    """
    :param title: str | None
    """

    # class="sec" => d:priority="2"
    # style="color:steelblue" => class="ex"
    # class="p" style="color:green" => class="p"
    # style="color:green" => class="c"
    # style="margin-left:{}em" => class="m{}"
    # <s> => <del>

    # xhtml is strict
    if BeautifulSoup:
        soup = BeautifulSoup.BeautifulSoup(body, from_encoding='utf-8')
        # difference between 'lxml' and 'html.parser'
        if soup.body:
            soup = soup.body

        for tag in soup(class_='sec'):
            tag['class'].remove('sec')
            if not tag['class']:
                del tag['class']
            tag['d:priority'] = "2"
        for tag in soup(lambda x: 'color:steelblue' in x.get('style', '')):
            remove_style(tag, 'color:steelblue')
            if 'ex' not in tag.get('class', []):
                tag['class'] = tag.get('class', []) + ['ex']
        for tag in soup(is_green):
            remove_style(tag, 'color:green')
            if 'p' not in tag.get('class', ''):
                tag['class'] = tag.get('class', []) + ['c']
        for tag in soup(True):
            if 'style' in tag.attrs:
                m = margin_re.search(tag['style'])
                if m:
                    remove_style(tag, m.group(0))
                    tag['class'] = tag.get('class', []) + ['m' + m.group(1)]
        for tag in soup.select('[href]'):
            href = tag['href']
            if not (href.startswith('http:') or href.startswith('https:')):
                tag['href'] = 'x-dictionary:d:%s' % href
        for tag in soup('u'):
            tag.name = 'span'
            tag['class'] = tag.get('class', []) + ['u']
        for tag in soup('s'):
            tag.name = 'del'

        if title:
            h1 = BeautifulSoup.Tag(name='h1')
            h1.string = title
            soup.insert(0, h1)
        # hence the name BeautifulSoup
        content = soup.encode_contents()
    else:
        # somewhat analogue to what BeautifulSoup suppose to do
        body = em0_9_re.sub(em0_9_sub, body)
        body = em0_9_ex_re.sub(em0_9_ex_sub, body)
        body = href_re.sub(href_sub, body)

        body = body \
            .replace('<i style="color:green">', '<i class="c">') \
            .replace('<i class="p" style="color:green">', '<i class="p">') \
            .replace('<span class="ex" style="color:steelblue">', '<span class="ex">') \
            .replace('<span class="sec ex" style="color:steelblue">', '<span class="sec ex">') \
            .replace('<u>', '<span class="u">').replace('</u>', '</span>') \
            .replace('<s>', '<del>').replace('</s>', '</del>')

        # nice header to display
        content = '<h1>%s</h1>%s' % (title, body) if title else body
        content = close_tag.sub('<\g<1> />', content)
        content = img_tag.sub('<img \g<1>/>', content)
    content = content.replace('&nbsp;', '&#160;')
    content = nonprintable.sub('', content)
    return content

def write_entries(glos, f, cleanHTML, indexes):
    """
    :param indexes: str | None
    """
    if cleanHTML:
        BeautifulSoup = get_beautiful_soup()
        if not BeautifulSoup:
            log.warn('cleanHTML option passed but BeautifulSoup not found.  '
                     'to fix this run `easy_install beautifulsoup4` or '
                     '`pip2 install beautifulsoup4`.')
    else:
        BeautifulSoup = None

    # write entries
    generate_id = id_generator()
    generate_indexes = indexes_generator(indexes)
    _buffer = ''

    xdxf.xdxf_init()

    glos.setDefaultDefiFormat('h')

    for i, entry in enumerate(glos):
        words = entry.getWords()
        word, alts = words[0], words[1:]
        defi = entry.getDefi()
        format = entry.getDefiFormat()
        
        long_title = _normalize.title_long(_normalize.title(word, BeautifulSoup))
        if not long_title:
            continue

        _id = next(generate_id)
        if BeautifulSoup:
            title_attr = BeautifulSoup.dammit.EntitySubstitution.substitute_xml(long_title, True)
        else:
            title_attr = '"%s"' % long_title

        begin_entry = '<d:entry id="%(id)s" d:title=%(title)s>\n' % {
            'id': _id,
            'title': title_attr,
        }

        if format == 'x':
            content = xdxf.xdxf_to_html(defi)
            content = format_clean_content(None, content, BeautifulSoup)
        else:
            content = defi
            content = format_clean_content(long_title, content, BeautifulSoup)

        indexes = generate_indexes(long_title, alts, content, BeautifulSoup)

        end_entry = '\n</d:entry>\n'

        _buffer += begin_entry
        _buffer += indexes
        _buffer += content
        _buffer += end_entry

        if i % 1000 == 0:
            f.write(_buffer)
            _buffer = ''
    f.write(_buffer)

def dictionary_end(glos, f):
    f.write('</d:dictionary>\n')


def write_xml(glos, filename, cleanHTML, frontBackMatter, indexes):
    with open(filename, 'wb') as f:
        dictionary_begin(glos, f, frontBackMatter)
        write_entries(glos, f, cleanHTML, indexes)
        dictionary_end(glos, f)
