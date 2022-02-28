import angr
from re import findall
from functools import lru_cache

class TB:
    def __init__(self, guest_pc, host_pc, size, q=None):
        self.guest_pc = guest_pc
        self.host_pc = host_pc
        self.size = size
        self.q=q
    
    @property
    def code(self):
        self.q.mem.seek(self.host_pc-self.q.base)
        return self.q.mem.read(self.size)
    
    @lru_cache(maxsize=None)
    def decompile(self):
        raise Exception("don't use this, it was a specific use case")
        q = angr.Project(
            io.BytesIO(self.code), 
            main_opts={
                'backend':'blob',
                'arch':'amd64',
                'base_addr': self.host_pc,
                # 'entry_point':a+11
            }
        )
        cfg = q.analyses.CFG(
            force_complete_scan=False,
            function_starts=[self.host_pc+11], 
            data_references=True, 
            normalize=True)
        q.arch.bp_offset=None
        src = q.analyses.Decompiler(
            cfg.functions[self.host_pc+11],
            cfg,
            sp_tracker_track_memory=False).codegen.text
        
        src = src[src.index('\n\n'):src.rindex('goto')]

        for i in range(0,32*4,4):
            src = src.replace(f'v0[{i}]',f'r{i//4}')
            src = src.replace(f'v2[{i}]',f'r{i//4}')
        
        
        
        src = sub('v0\[1036\] = \d+;\n    ','',src, 0, re.DOTALL)
        src = sub('v0\[136\] = \d+;\n    ','',src, 0, re.DOTALL)
        
        
        src = src.replace('r29','sp')
        src = src.replace('v0[128]','pc')
        src = src.replace('v0->field_80','pc')
        src = src.replace('v2[128]','pc')
        src = src.replace('v2->field_80','pc')

        src = src.replace('*(v1:(long long)','*(')
        
        src = sub('if \(\(char\)\[D\] amd64g_calculate_condition.*}\n','',src, 0, re.DOTALL)

        if '()' in src:
            addr = findall('(\d+)\(\);',src)[0]
            sym = self.q._exec(f'info symbol {addr}').strip()
            sym = sym[:sym.index(' ')]
            src = f'{sym}()'


        
        if 'if' not in src:
            src = src.replace(f'pc = {self.guest_pc+4};\n    ','')
        num = findall('pc = (\d+);',src)
        for n in num:
            src = src.replace(n, hex(int(n)))
        

        src = src.strip()
        self.source = src