import os
import re
import tempfile
from subprocess import Popen, PIPE

from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import HtmlFormatter
from pygments.styles.native import NativeStyle

from binaryninja.log import log_error
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import show_message_box, show_html_report
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

ARCHS = ['x86', 'mips', 'powerpc', 'arm']
BG_COLOR = '#272811'

class RetDec(object):
    def __init__(self, view, function):
        self._view = view
        self._function = function

        self.arch = self._view.arch.name
        if self.arch not in ARCHS:
            show_message_box('RetDec Offline Decompiler',
                             'Only {} architectures are supported'.format(', '.join(ARCHS)),
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
            raise Exception('unsupported architecture')

        self.endianness = 'big' if self._view.endianness else 'little'

        self.cmdline = ['retdec-decompiler.sh']
        self.cmdline.append('-m')
        self.cmdline.append('raw')

        self.cmdline.append('-a')
        self.cmdline.append(self.arch)

        self.cmdline.append('-e')
        self.cmdline.append(self.endianness)

        self.cmdline.append('--backend-no-debug-comments')
        self.cmdline.append('--cleanup')

    def decompile_function(self):
        filename = self.read_function()

        p = Popen(self.cmdline, stdout=PIPE, stderr=PIPE)
        err = p.communicate()[1]
        if err.startswith('Error'):
            raise Exception(err)

        with open('{}.c'.format(filename), 'r') as f:
            code = f.read()

        os.unlink('{}.c'.format(filename))
        os.unlink('{}.c.frontend.dsm'.format(filename))

        code = self.merge_symbols(code)
        self.render_output(code)

    def read_function(self):
        start = self._function.start
        end = max([bb.end for bb in self._function.basic_blocks])
        raw = self._view.read(start, end - start)

        fd, filename = tempfile.mkstemp()
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)

        self.cmdline.append('--raw-section-vma')
        self.cmdline.append('{:#x}'.format(start))

        self.cmdline.append('--raw-entry-point')
        self.cmdline.append('{:#x}'.format(start))

        self.cmdline.append(filename)
        return filename

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

def decompile(view, function):
    try:
        retdec = RetDec(view, function)
        retdec.decompile_function()
    except Exception as e:
        log_error('failed to decompile function\n{}'.format(e.message))

PluginCommand.register_for_function('RetDec Offline Decompiler', 'Decompile', decompile)
