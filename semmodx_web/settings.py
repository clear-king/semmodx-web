"""
Settings for SemModX Web, read from settings.ini next to serve.py.

Every machine-specific path lives here instead of in the code. A missing or
unreadable settings.ini is reported with the exact path and what to put in it,
the same way the plugin reports a missing config.ini.
"""

import configparser
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(PROJECT_ROOT, "settings.ini")


class SettingsError(RuntimeError):
    pass


def _default_ida_python():
    # The worker must run on the interpreter IDA is bound to; serve.py itself
    # usually is that interpreter, so it is the natural default.
    return sys.executable


class Settings(object):
    def __init__(self, path=SETTINGS_PATH):
        self.path = path
        if not os.path.isfile(path):
            raise SettingsError(
                "settings.ini was not found at:\n  %s\n\n"
                "Copy settings.ini.example to settings.ini in the same folder and set\n"
                "[ida] install_dir to your IDA Pro 9.x installation." % path)
        cp = configparser.RawConfigParser()
        try:
            cp.read(path, encoding="utf-8")
        except (configparser.Error, UnicodeDecodeError) as e:
            raise SettingsError("settings.ini could not be read:\n  %s\n\n%s" % (path, e))
        self._cp = cp

        self.ida_dir = self._path("ida", "install_dir")
        if not self.ida_dir:
            raise SettingsError("[ida] install_dir is empty in %s" % path)
        self.python = self._path("ida", "python") or _default_ida_python()
        # Where `import semmodx` resolves from: the plugin as installed in IDA.
        self.plugin_parent = self._path("semmodx", "plugin_dir") or os.path.join(self.ida_dir, "plugins")

        self.host = self._get("server", "host", "127.0.0.1")
        self.port = int(self._get("server", "port", "6001"))

        self.workspace = self._path("storage", "workspace") or os.path.join(PROJECT_ROOT, "workspace")
        self.upload_dir = self._path("storage", "upload_dir") or os.path.join(self.workspace, "uploads")
        self.log_dir = self._path("storage", "log_dir") or os.path.join(PROJECT_ROOT, "logs")
        self.max_upload_mb = int(self._get("storage", "max_upload_mb", "2048"))
        extra = self._get("storage", "database_dirs", "")
        self.database_dirs = [self._abspath(p.strip()) for p in extra.split(";") if p.strip()]

    # -- helpers -------------------------------------------------------------
    def _get(self, section, option, default=None):
        if self._cp.has_option(section, option):
            v = self._cp.get(section, option).strip()
            if v:
                return v
        return default

    def _abspath(self, p):
        p = os.path.expandvars(os.path.expanduser(p))
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(PROJECT_ROOT, p))

    def _path(self, section, option):
        v = self._get(section, option)
        return self._abspath(v) if v else None

    @property
    def plugin_config(self):
        return os.path.join(self.plugin_parent, "semmodx", "config.ini")

    def problems(self):
        """Environment checks that are cheap to run before starting the server."""
        out = []
        if not os.path.isfile(os.path.join(self.ida_dir, "idalib.dll" if os.name == "nt" else
                                           ("libidalib.dylib" if sys.platform == "darwin" else "libidalib.so"))):
            out.append("IDA library not found in [ida] install_dir = %s" % self.ida_dir)
        if not os.path.isfile(self.python):
            out.append("[ida] python does not exist: %s" % self.python)
        if not os.path.isdir(os.path.join(self.plugin_parent, "semmodx")):
            out.append("SemModX plugin not found under %s (set [semmodx] plugin_dir)" % self.plugin_parent)
        elif not os.path.isfile(self.plugin_config):
            out.append("SemModX config.ini missing: %s (copy config.ini.example and add an api_key)"
                       % self.plugin_config)
        return out


_settings = None


def get_settings():
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
