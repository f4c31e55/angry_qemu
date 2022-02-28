import logging, atexit, io, json
import avatar2
logging.getLogger('avatar').setLevel(logging.CRITICAL+1)

from functools import lru_cache
from re import findall, sub
from pwnlib.tubes.process import process
logging.getLogger('pwnlib.tubes.process').setLevel(logging.WARNING)

from .t import TB

class QEMU_Proxy:
    def __init__(self, cmd):
        self.log = logging.getLogger('angry_qemu')
        self.mem = io.BytesIO()
        
        self.log.info('init')
        self.h2g = dict()
        self._setup_target(cmd)
        self._lift_first_block()
    
    def __del__(self):
        self.log.info('del')
        self.proc.kill()
        self.avatar.shutdown()
    
    def _setup_target(self, cmd):
        self.proc = process(cmd)
        self.proc.clean()
        self.avatar = avatar2.Avatar(arch=avatar2.archs.x86.X86_64, log_to_stdout=False)
        self.avatar.load_plugin('gdb_memory_map_loader')
        self.target = self.avatar.add_target(avatar2.GDBTarget, gdb_port=1235)
        self.target.init()

        b = self.target.bp('do_init_thread')
        self.target.cont()
        self.target.wait()
        self.target.remove_breakpoint(b)
        for _ in range(10):self.target.step()#ouch
        
        r = self._exec('p *infop')[1:-2]
        r = sub(r'\$\d+ = \{',r'{',r)
        r = sub('(\w+) = ', r'"\1":',r)
        r = sub('0x0','0',r)
        j = json.loads(r)
        self.load_bias = j["load_bias"]
        self.start_code = j["start_code"]
        self.end_code = j["end_code"]
        self.start_data = j["start_data"]
        self.end_data = j["end_data"]
        self.brk = j["brk"]
        self.stack_limit = j["stack_limit"]
        self.entry = j["entry"]

        b = self.target.bp('tb_find')
        self.target.cont()
        self.target.wait()
        self.target.remove_breakpoint(b)
        self.target.load_memory_mappings()

        atexit.register(self.__del__)

    def _exec(self, cmd):
        b,s = self.target.protocols.execution.console_command(cmd)
        if not b: raise Exception(f'QEMU proxy failed to run {cmd}')
        return s

    def _lift_first_block(self):
        r = self._exec(f"p cpu->env_ptr")
        self.initial_ctx_addr = int(findall(' (0x[0-9a-f]+)',r)[0],16)

        r = self._exec(f"p sizeof(CPUArchState)") #TODO: make this more efficient
        env_size = int(findall(' = ([0-9]+)',r)[0])
        self.initial_ctx = self.target.rm(self.initial_ctx_addr, 1, env_size, raw=True)

        try: #oof
            r = self._exec(f"p tcg_ctxs->code_gen_prologue")
        except Exception:
            r = self._exec(f"p tcg_ctxs->code_buf")
        self.base = int(findall(' (0x[0-9a-f]+)',r)[0],16)
        
        if 'struct tb_tc' in self._exec(f"ptype TranslationBlock"):
            self.tb_find = self.tb_find2
        else:
            self.tb_find = self.tb_find1

    @lru_cache(None)
    def lift(self, guest_pc, thumb=None):
        if self.log.isEnabledFor(logging.DEBUG): self.log.debug(f"new guest_pc 0x{guest_pc:x}")
        
        #FIXME: offsetof
        # anything but hexagon
        self.target.wm(self.initial_ctx_addr+0x80, 4, guest_pc)
        # hexagon
        self.target.wm(self.initial_ctx_addr+0xa4, 4, guest_pc)
        # thumb
        if thumb is not None: self.target.wm(self.initial_ctx_addr+0x408, 4, thumb)

        p,s = self.tb_find()

        m = self.target.rm(p,1,s,raw=True)
        self.h2g[p] = guest_pc
        self.mem.seek(p-self.base); self.mem.write(m)
        return TB(guest_pc, p, s, self)
    
    def tb_find1(self):
        r = self._exec(f"p/x *tb_find($rdi, $rsi, $rdx)")
        tcp,tcs = findall('tc_ptr = (0x[0-9a-f]+),.*tc_search = (0x[0-9a-f]+),',r)[0]
        return int(tcp,16), int(tcs,16)-int(tcp,16)
    
    def tb_find2(self):
        r = self._exec(f"p/x tb_find($rdi, $rsi, $rdx, $rcx)->tc")
        p,s = findall('ptr = (0x[0-9a-f]+).*size = (0x[0-9a-f]+)',r)[0]
        return int(p,16),int(s,16)

