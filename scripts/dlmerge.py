#!/usr/bin/env python3
'''
Merge https://github.com/v2fly/domain-list-community to one single file.
The four type: domain, full, keyword and regexp, only support domain and full.
Multi-tags syntax is not supported. (So far it doesn't seem to be used.)
'''

import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--datadir', default='data')
args = parser.parse_args()

datadir = args.datadir

tag2rule = {
    'ads': 'block',
    'cn': 'direct',
    '!cn': 'forward',
}

rule_re = re.compile(r'^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?')


def load_rule(rules_file, default_tag):
    for line in open(f'{datadir}/{rules_file}'):
        res = rule_re.match(line.strip())
        if res is None:
            continue
        cmd = res[2] or 'domain'
        tgt = res[3].strip()
        tag = res[5] or default_tag
        rule = tag2rule[tag]
        if cmd in ('domain', 'full'):
            print(f'{rule}\t{tgt}')
        elif cmd == 'include':
            load_rule(tgt, default_tag)


load_rule('cn', 'cn')
load_rule('geolocation-!cn', '!cn')
