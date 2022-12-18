from os.path import join as pjoin
from distutils.core import setup

setup(
        name = 'mdnsanalyzer',
        version = '0.1',
        scripts=[pjoin('bin', 'mdnsanalyzer')]
        version='1.0',
        description='Utility to passively analyze the incoming MDNS traffic',
        author='Bartosz Burgiel',
        author_email='bartek.burgiel@hotmail.com',
    )
