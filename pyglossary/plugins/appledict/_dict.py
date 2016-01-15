# -*- coding: utf-8 -*-
## appledict/_appledict.py
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

import hashlib
import re

def truncate(text, length=449):
    """
    trunct a string to given length
    :param str text:
    :return: truncated text
    :rtype: str
    """
    content = re.sub('(\t|\n|\r)', ' ', text)
    if (len(text)>length):
        # find the next space after max_len chars (do not break inside a word)
        pos = content[:length].rfind(' ')
        if pos == -1:
            pos = length
        text = text[:pos]
    return text

def dictionary_begin(glos, f, frontBackMatter):
    # progress bar
    if glos.ui:
        glos.ui.progressStart()

    # write header
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<d:dictionary xmlns="http://www.w3.org/1999/xhtml" xmlns:d="http://www.apple.com/DTDs/DictionaryService-1.0.rng">\n')

    if frontBackMatter:
        with open(frontBackMatter, 'r') as front_back_matter:
            f.write(front_back_matter.read())

def get_beautiful_soup():
    try:
        from bs4 import BeautifulSoup
    except:
        try:
            from BeautifulSoup import BeautifulSoup
        except:
            return None
    return BeautifulSoup

def id_generator():
    # closure
    entry_ids = set([])

    def generate_id(title):
        # use MD5 hash of title string as id
        id = '_' + hashlib.md5(title).hexdigest()

        # check entry id duplicates
        while id in entry_ids:
            id += '_'
        entry_ids.add(id)
        return id

    return generate_id

def indexes_generator():
    # it will be factory that atcs according to glossary language
    def generate_indexes(title, alts):
        s = '    <d:index d:value="%s"/>\n'%truncate(title)
        #   alternative items as index also
        for alt in alts:
            if alt != title:
                s += '    <d:index d:value="%s"/>\n'%truncate(alt)
        return s
    return generate_indexes


close_tag = re.compile('<(BR|HR)>', re.IGNORECASE)
nonprintable = re.compile('[\x00-\x07\x0e-\x1f]')
img_tag = re.compile('<IMG (.*?)>', re.IGNORECASE)

def format_clean_content(title, body, BeautifulSoup):
    # nice header to display
    content = ('<h1>%s</h1>\n'%title) + body
    # xhtml is strict
    if BeautifulSoup:
        soup  = BeautifulSoup(content, from_encoding='utf8')
        content = str(soup)
    else:
        content = close_tag.sub('<\g<1> />', content)
        content = img_tag.sub('<img \g<1>/>', content)
    content = content.replace('&nbsp;', '&#160;')
    content = nonprintable.sub('', content)
    return content


title_re = re.compile('<[^<]+?>|"|[<>]|\xef\xbb\xbf')

def normilize_title(title):
    """strip double quotes and html tags."""
    return title_re.sub('', title)


def write_entries(glos, f, cleanHTML):
    if cleanHTML:
        BeautifulSoup = get_beautiful_soup()
    else:
        BeautifulSoup = None

    # write entries
    generate_id = id_generator()
    generate_indexes = indexes_generator()
    total = float(len(glos.data))

    for i, item in enumerate(glos.data):
        title = normilize_title(item[0])
        if not title:
            continue

        id = generate_id(title)

        begin_entry = '<d:entry id="%(id)s" d:title="%(title)s">\n' % {
            'id': id,
            'title': truncate(title.replace('&', '&amp;'), 1126)
        }
        f.write(begin_entry)

        # get alternatives list
        try:
            alts = item[2]['alts']
        except:
            alts = []

        indexes = generate_indexes(title, alts)
        f.write(indexes)

        content = format_clean_content(title, item[1], BeautifulSoup)
        f.write(content)

        end_entry = '\n</d:entry>\n'
        f.write(end_entry)

        if i % 1000 == 0 and glos.ui:
            glos.ui.progress(i / total)

def dictionary_end(glos, f):
    f.write('</d:dictionary>\n')

    # end progress bar
    if glos.ui:
        glos.ui.progressEnd()

def write_xml(glos, filename, cleanHTML, frontBackMatter):
    with open(filename, 'wb') as f:
        dictionary_begin(glos, f, frontBackMatter)
        write_entries(glos, f, cleanHTML)
        dictionary_end(glos, f)
