import os
import re
import tempfile
import json
import abc
from subprocess import Popen, PIPE

from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import HtmlFormatter
from pygments.styles.native import NativeStyle

from binaryninja import log
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import show_message_box, show_html_report
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

BG_COLOR = '#272811'


class ExceptionWithMessageBox(Exception):
    def __init__(self, msg, info, icon=MessageBoxIcon.InformationIcon):
        super(ExceptionWithMessageBox, self).__init__(msg)
        show_message_box(msg, info, MessageBoxButtonSet.OKButtonSet, icon)


class RetDecConfig(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def dump(self):
        pass


class RetDecFunctionConfig(RetDecConfig):
    CALLING_CONVENTIONS = ["CC_UNKNOWN",
                           "CC_VOIDARG",
                           "CC_CDECL",
                           "CC_ELLIPSIS",
                           "CC_STDCALL",
                           "CC_PASCAL",
                           "CC_FASTCALL",
                           "CC_THISCALL",
                           "CC_MANUAL",
                           "CC_SPOILED",
                           "CC_SPECIALE",
                           "CC_SPECIALP",
                           "CC_SPECIAL"]

    def __init__(self, start_addr):
        self._conf = {'startAddr': str(start_addr)}

    @property
    def calling_convention(self):
        return self._conf['CallingConvention']

    @calling_convention.setter
    def calling_convention(self, calling_convention):
        if calling_convention not in self.CALLING_CONVENTIONS:
            msg = 'unsupported calling convention: {}'.format(calling_convention)
            calling_conventions = ', '.join(self.CALLING_CONVENTIONS)
            info = 'Only {} calling conventions are supported'.format(calling_conventions)
            raise ExceptionWithMessageBox(msg, info)
        self._conf['CallingConvention'] = calling_convention

    def dump(self):
        return self._conf


class RetDecMainConfig(RetDecConfig):
    ARCHS = ['x86', 'mips', 'powerpc', 'arm']
    ENDIANNESS = ['big', 'little']

    def __init__(self):
        self._conf = {'architecture': {},
                      'functions': []}

    @property
    def arch(self):
        return self._conf['architecture']['name']

    @arch.setter
    def arch(self, arch):
        if arch not in self.ARCHS:
            msg = 'unsupported architecture: {}'.format(arch)
            info = 'Only {} architectures are supported'.format(', '.join(self.ARCHS))
            raise ExceptionWithMessageBox(msg, info)
        self._conf['architecture']['name'] = arch

    @property
    def endianness(self):
        return self._conf['architecture']['endianness']

    @endianness.setter
    def endianness(self, endianness):
        if endianness not in self.ENDIANNESS:
            msg = 'unsupported endianness: {}'.format(endianness)
            info = 'Only {} endianness are supported'.format(', '.join(self.ENDIANNESS))
            raise ExceptionWithMessageBox(msg, info)
        self._conf['architecture']['endianness'] = endianness

    def add_function(self, func):
        """Add configuration of a function"""
        self._conf['functions'].append(func)

    def dump(self):
        """Dump configuration into open file output in json format"""
        conf = self._conf
        conf['functions'] = [function.dump() for function in conf['functions']]
        return conf


class RetDecConfigFactory(object):
    CC_TRANSLATE = {'unknown': "CC_UNKNOWN",
                    'voidarg': "CC_VOIDARG",
                    'cdecl': "CC_CDECL",
                    'ellipsis': "CC_ELLIPSIS",
                    'stdcall': "CC_STDCALL",
                    'pascal': "CC_PASCAL",
                    'fastcall': "CC_FASTCALL",
                    'thiscall': "CC_THISCALL",
                    'manual': "CC_MANUAL",
                    'spoiled': "CC_SPOILED",
                    'speciale': "CC_SPECIALE",
                    'specialp': "CC_SPECIALP",
                    'special': "CC_SPECIAL"}

    @classmethod
    def main(cls, view):
        conf = RetDecMainConfig()
        conf.arch = view.arch.name
        conf.endianness = 'big' if view.endianness else 'little'
        return conf

    @classmethod
    def func(cls, function):
        conf = RetDecFunctionConfig(function.start)
        conf.calling_convention = cls.CC_TRANSLATE[function.calling_convention.name]
        return conf


class RetDec(object):
    def __init__(self, view, function):
        self._view = view
        self._function = function

        self.conf = RetDecConfigFactory.main(self._view)
        self.conf.add_function(RetDecConfigFactory.func(self._function))

        self._cmdline = ['retdec-decompiler.py']
        self._cmdline.append('--backend-no-debug-comments')
        self._cmdline.append('--cleanup')

    def decompile(self, inputfile):
        # On Windows, autodeleting temp files are locked by their owning process,
        # meaning you can't use them to pass input to other programs. Using delete=False and
        # unlinking after is an accepted workaround for this.
        # See https://bugs.python.org/issue14243
        tmpfilename = None
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as conf:
            tmpfilename = conf.name
            json.dump(self.conf.dump(), conf)
            conf.flush()
            self._cmdline.extend(['--config', conf.name])
            self._cmdline.append(inputfile)
            log.log_info(" ".join(self._cmdline))

            shell = False
            if os.name == 'nt':
                shell = True
            p = Popen(self._cmdline, stdout=PIPE, stderr=PIPE, shell=shell)
            _, err = p.communicate()
            log.log_info(err)
            if err.startswith('Error'):
                raise ExceptionWithMessageBox('decompilation error', err)

            with open('{}.c'.format(inputfile), 'r') as f:
                code = f.read()

            os.unlink('{}.c'.format(inputfile))
            f = '{}.c.frontend.dsm'.format(inputfile)
            if os.path.exists(f):
                os.unlink(f)

        os.unlink(tmpfilename)

        return code

    def decompile_raw(self):
        self._cmdline.extend(['--mode', 'raw'])
        self._cmdline.extend(['--raw-section-vma', '{:#x}'.format(self._function.start)])
        self._cmdline.extend(['--raw-entry-point', '{:#x}'.format(self._function.start)])
        self._cmdline.extend(['--arch', self.conf.arch])
        self._cmdline.extend(['--endian', self.conf.endianness])

        tmpfilename = None
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as f:
            tmpfilename = f.name
            self.load_function(f)

            code = self.decompile(f.name)

        os.unlink(tmpfilename)

        code = self.merge_symbols(code)
        self.render_output(code)

    def load_function(self, output):
        start = self._function.start
        end = max([bb.end for bb in self._function.basic_blocks])
        raw = self._view.read(start, end - start)

        output.write(raw)
        output.flush()

    def decompile_bin(self):
        self._cmdline.extend(['--mode', 'bin'])
        self._cmdline.extend(['--arch', self.conf.arch])
        self._cmdline.extend(['--endian', self.conf.endianness])
        self._cmdline.extend(['--select-ranges', '{:#x}-{:#x}'.format(self._function.start,
                                                                      self._function.start+1)])

        tmpfilename = None
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as f:
            tmpfilename = f.name
            self.load_bin(f)

            code = self.decompile(f.name)

        os.unlink(tmpfilename)

        code = self.merge_symbols(code)
        self.render_output(code)

    def load_bin(self, output):
        output.write(self._view.file.raw.read(0, len(self._view.file.raw)))

    def merge_symbols(self, code):
        pcode = []
        pattern = re.compile(r'(unknown_|0x)([a-f0-9]+)')

        for line in code.splitlines():
            if line.strip().startswith('//') or line.strip().startswith('#'):
                pcode.append(line)
                continue

            if 'entry_point' in line:
                line = self.replace_symbols(line, self._function.start, 'entry_point')

            for match in pattern.findall(line):
                address = int(match[1], 16)
                line = self.replace_symbols(line, address, ''.join(match))

            pcode.append(line)

        return '\n'.join(pcode)

    def replace_symbols(self, line, address, string):
        symbol = self._view.get_symbol_at(address)
        if symbol is not None:
            return line.replace(string, symbol.name)

        function = self._view.get_function_at(address)
        if function is not None:
            return line.replace(string, function.name)

        return line

    def render_output(self, code):
        lexer = CLexer()
        style = NativeStyle()
        style.background_color = BG_COLOR
        formatter = HtmlFormatter(full=True, style='native', noclasses=True)
        colored_code = highlight(code, lexer, formatter)
        show_html_report('{}.c'.format(self._function.name), colored_code)

def decompile_raw(view, function):
    try:
        retdec = RetDec(view, function)
        retdec.decompile_raw()
    except Exception as e:
        log.log_error('failed to decompile function: {}'.format(e))

def decompile_bin(view, function):
    try:
        retdec = RetDec(view, function)
        retdec.decompile_bin()
    except Exception as e:
        log.log_error('failed to decompile function: {}'.format(e))

PluginCommand.register_for_function('RetDec Offline Decompiler', 'Decompile-Fast', decompile_raw)
PluginCommand.register_for_function('RetDec Offline Decompiler (Full Binary Analysis)',
                                    'Decompile-Slow', decompile_bin)
