#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import codecs
from enocean.protocol.eep import EEP

ROW_FORMAT = '|{:8s}|{:50s}|{:8s}|{:70s}|\n'


def generate(f_handle):
    eep = EEP()
    f_handle.write('# Supported profiles\n')
    f_handle.write('All profiles (should) correspond to the official [EEP](http://www.enocean-alliance.org/eep/) by EnOcean.\n\n')

    for telegram in eep.tree.getroot().iter('telegram'):
        f_handle.write('<details open><summary>%s <i>(%s)</i></summary><blockquote>\n' % (telegram.get('rorg')[2:], telegram.get('description')))
        for func in telegram.iter('profiles'):
            # f_handle.write('#####  FUNC %s - %s\n' % (func.get('func'), func.get('description')))
            f_handle.write('<details open><summary>%s <i>(%s)</i></summary><blockquote>\n' % (func.get('func')[2:], func.get('description')))
            for profile in func.iter('profile'):
                f_handle.write('<details><summary>%s-%s-%s <i>(%s)</i></summary><blockquote>\n\n' % (telegram.get('rorg')[2:],
                                                      func.get('func')[2:],
                                                      profile.get('type')[2:],
                                                      profile.get('description')))

                for data in profile.iter('data'):
                    header = []

                    if data.get('direction'):
                        header.append('direction: %s' % (data.get('direction')))
                    if data.get('command'):
                        header.append('command: %s' % (data.get('command')))

                    if header:
                        f_handle.write('###### %s\n' % ' '.join(header))

                    f_handle.write(ROW_FORMAT.format('shortcut', 'description', 'type', 'values'))
                    f_handle.write(ROW_FORMAT.format('--------', '--------------------------------------------------', '--------', '----'))
                    for child in data:
                        values = []
                        for item in child:
                            if item.tag == 'rangeitem':
                                values.append('%s-%s - %s' % (item.get('start'), item.get('end'), item.get('description')))
                            elif item.tag == 'item':
                                values.append('%s - %s' % (item.get('value'), item.get('description')))
                            elif item.tag == 'range':
                                range_min = float(item.find('min').text)
                                range_max = float(item.find('max').text)
                                scale = child.find('scale')
                                scale_min = float(scale.find('min').text)
                                scale_max = float(scale.find('max').text)

                                values.append('%s-%s ↔ %s-%s %s' % (range_min, range_max, scale_min, scale_max, child.get('unit')))
                        if not values:
                            f_handle.write(ROW_FORMAT.format(child.get('shortcut'), child.get('description'), child.tag, ''))
                            continue

                        f_handle.write(ROW_FORMAT.format(child.get('shortcut'), child.get('description'), child.tag, values[0]))
                        for i in range(1, len(values)):
                            f_handle.write(ROW_FORMAT.format('', '', '', values[i]))
                    f_handle.write('\n')

                f_handle.write('</blockquote></details>\n\n')

            f_handle.write('</blockquote></details>\n\n')
        f_handle.write('</blockquote></details>\n')


if __name__ == '__main__':
    with codecs.open('SUPPORTED_PROFILES.md', 'w', 'utf-8') as f_handle:
        generate(f_handle)
