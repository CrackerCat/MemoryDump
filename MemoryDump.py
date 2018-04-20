# -*- coding: UTF-8 -*-
import idaapi


class MemoryDumpForm(idaapi.Form):
    """Simple Form to test  and combo box controls"""
    def __init__(self):
        idaapi.Form.__init__(self, r"""STARTITEM 0
        MemoryDump
        {FormChangeCb}
        Please Input Addr:
        <#Hint1#StartAddr  :{StartAddress}>
        <#Hint2#EndAddr/Len:{EndAddress}>
        <##Option##Len:{rLen}>
        <EndAddr:{rEndAddr}>{cGroup2}>
        """, {
            'StartAddress': idaapi.Form.StringInput(width=50, swidth=15),
            'EndAddress': idaapi.Form.StringInput(width=50, swidth=15),
            'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange),
            'cGroup2': idaapi.Form.RadGroupControl(("rLen", "rEndAddr")),
        })

    def OnFormChange(self, fid):
        if fid == -2:
            # print "start save"
            self.start = self.GetControlValue(self.StartAddress)
            self.endorlen = self.GetControlValue(self.EndAddress)
            self.dumptype = self.GetControlValue(self.cGroup2)
            if len(self.start) == 0 or len(self.endorlen) == 0:
                idaapi.warning("addr or len is null")
                return -1
            else:
                self.StartDump()
        return 1

    def StartDump(self):
        # print self.start
        # print self.endorlen
        self.filepath = idaapi.ask_file(1, "*.dump", "save dump file")
        if self.dumptype == 0:
            ea = self.getHexNum(self.start)
            len = self.getHexNum(self.endorlen)
            if not idaapi.is_loaded(ea) or not idaapi.is_loaded(ea + len):
                idaapi.warning("arrary is out of bound")
                return -1
            if len <= 0:
                idaapi.warning("len is <= zore")
                return -1
            print("start read bytes")
            self.Close(0)
            idaapi.show_wait_box("read bytes")
            self.memdata = idaapi.get_many_bytes(ea, len)
            print("read bytes end")
            idaapi.hide_wait_box("read end")
        elif self.dumptype == 1:
            ea = self.getHexNum(self.start)
            len = self.getHexNum(self.endorlen) - self.getHexNum(self.start)
            if not idaapi.is_loaded(ea) or not idaapi.is_loaded(ea + len):
                idaapi.warning("arrary is out of bound")
                return -1
            if len <= 0:
                idaapi.warning("len is <= zore")
                return -1
            print("start read bytes")
            self.Close(0)
            idaapi.show_wait_box("read bytes")
            self.memdata = idaapi.get_many_bytes(ea, len)
            print("read bytes end")
            idaapi.hide_wait_box("read end")
        fp = open(self.filepath, 'wb')
        fp.write(self.memdata)
        fp.close()
        idaapi.msg("save:" + self.filepath)
        return 1

    def getHexNum(self, nums):
        return long(nums, 16)


class memory_dump_handle(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        #print "start show"
        form = MemoryDumpForm()
        form.Compile()
        form.Execute()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MemoryDump(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Memory Dump for IDA Pro 7.0 and 7.1"
    help = "Memory Dump"
    wanted_name = "MemoryDump"
    wanted_hotkey = ""

    def init(self):
        idaapi.msg("Ida plugin init called.\n")
        idaapi.register_action(
            idaapi.action_desc_t("dump:memoryDump", "MemoryDump", memory_dump_handle(), "Alt+D", "", -1))
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action("dump:memoryDump")
        idaapi.msg("term was called \n")

    def run(self):
        idaapi.msg("run was called \n")
        pass


def PLUGIN_ENTRY():
    return MemoryDump()
