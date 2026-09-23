#!/usr/bin/env python3
"""Compile real portable code, execute tests, retain every RED/GREEN output."""
import os
import pathlib
import subprocess
import sys
here=pathlib.Path(__file__).resolve().parent
root=here.parents[1]
build=here/'.build'
build.mkdir(exist_ok=True)
sources=[root/'firmware/radio/radio_config.c']
for name in ('http_parser.c','dhcp_wire.c','entropy_fill.c'):
    if (root/'firmware/radio'/name).exists(): sources.append(root/'firmware/radio'/name)
cmd=['cc','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared','-g',
     *map(str,sources),'-o',str(build/'parsers.so')]
with (here/'tdd.log').open('a') as log:
    for args in (cmd,[sys.executable,str(here/'test_parsers.py'),'-v',*sys.argv[1:]]):
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        text='$ '+' '.join(args)+'\n'+result.stdout+'exit='+str(result.returncode)+'\n'
        print(text,end=''); log.write(text); log.flush()
        if result.returncode: sys.exit(result.returncode)
