import logging
import os

from linktools import BaseEnviron

from environment.version import __name__ as __module_name__, __version__ as __module_version__


class Environ(BaseEnviron):


    root_path = os.path.dirname(os.path.dirname(__file__))
    configs_path = os.path.join(root_path, "configs")
    file_path = os.path.join(root_path, "static")
    module_path = os.path.join(root_path, "modules")
    log_path = os.path.join(file_path, "log")
    temp_path = os.path.join(file_path, "temp")

    def __init__(self):
        self.config.update_from_dir(self.configs_path)


    @property
    def name(self) -> str:
        return __module_name__

    @property
    def version(self) -> str:
        return __module_version__


environ = Environ()
