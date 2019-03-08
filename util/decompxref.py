import idaapi
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui

done_funcs = {}
data = []

def get_args(xref, needle):
    cf = GetFunctionName(xref.frm)

    decomp = None

    if cf in done_funcs:
        decomp = done_funcs[cf]
    else:
        decomp = idaapi.decompile(xref.frm)
        done_funcs[cf] = decomp

    # todo: parse decomp tree cause this is actually total shit...

    call = ""
    foundNeedle = False
    for line in str(decomp).split('\n'):
        if needle in line or foundNeedle:
            foundNeedle = True
            call = call + line.strip()
            if ";" in line:
                data.append((xref.frm, cf, call.strip()))
                return

def run(ea):
    func = idaapi.get_func(ea)
    needle = GetFunctionName(ea)
    
    # get all xrefs
    for xref in XrefsTo(func.startEA):
        get_args(xref, needle)

    ui = ArgsXrefOutput()
    ui.Show(needle)

class ArgsXrefOutput(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()


    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()

        self.table = QtWidgets.QTableWidget()
        layout.addWidget(self.table)

        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Address"))
        self.table.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Caller"))
        self.table.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem("Decompilation"))

        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 1000)

        self.table.cellDoubleClicked.connect(self.double_clicked)

        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.parent.setLayout(layout)

        self.fill_table()

    def fill_table(self):
        self.table.setRowCount(len(data))

        row = 0
        for item in data:
            addr, callee, args = item

            item = QtWidgets.QTableWidgetItem('0x%X' % addr)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(row, 0, item)

            item = QtWidgets.QTableWidgetItem(callee)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(row, 1, item)

            item = QtWidgets.QTableWidgetItem(args)
            self.table.setItem(row, 2, item)

            row += 1

        self.table.resizeRowsToContents()

    def double_clicked(self, row, column):
        if column == 2:
            return

        addr, callee, args = data[row]
        
        idc.Jump(addr)


    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        pass

    def Show(self, name):
        return PluginForm.Show(self, "Decompiled xrefs for: " + str(name))

class decomp_xref_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL

    wanted_name = "Decompile Xrefs"
    wanted_hotkey = "shift+x"

    comment = 'Gets decompiled arguments used to call selected function'
    help = 'no'
 
    def init(self):
        return idaapi.PLUGIN_OK
 
    def run(self, arg):
        run(ScreenEA())
 
    def term(self):
        pass
 
def PLUGIN_ENTRY():
    return decomp_xref_t()