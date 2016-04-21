from formats_common import *

enable = False
format = 'Unknown'
description = 'Unknown'
extentions = []
readOptions = []
writeOptions = []
supportsAlternates = False

import sys, os
sys.path.append('/usr/share/pyglossary')

from os.path import splitext
from os.path import split as path_split
from os.path import join as path_join
import logging

from pyglossary import core
from pyglossary.file_utils import FileLineWrapper

log = logging.getLogger('root')

class chdir:
    """
    mkdir + chdir shortcut to use with `with` statement.

        >>> print(os.getcwd())  # -> "~/projects"
        >>> with chdir('my_directory', create=True):
        >>>     print(os.getcwd())  # -> "~/projects/my_directory"
        >>>     # do some work inside new 'my_directory'...
        >>> print(os.getcwd())  # -> "~/projects"
        >>> # automatically return to previous directory.
    """
    def __init__(self, directory, create=False, clear=False):
        self.oldpwd = None
        self.dir = directory
        self.create = create
        self.clear = clear

    def __enter__(self):
        import shutil
        self.oldpwd = os.getcwd()
        if os.path.exists(self.dir):
            if self.clear:
                shutil.rmtree(self.dir)
                os.makedirs(self.dir)
        elif self.create:
            os.makedirs(self.dir)
        os.chdir(self.dir)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.oldpwd)
        self.oldpwd = None
