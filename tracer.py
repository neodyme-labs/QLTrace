from qiling import Qiling
import sqlite3
from typing import Any
from qiling.os.thread import QlThread


class Tracer:

    def __init__(self, ql: Qiling, path="trace.db"):
        self.ql: Qiling = ql
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS info (key TEXT PRIMARY KEY, value TEXT);"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS lib (name TEXT, base TEXT, end TEXT);"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS bbl (addr TEXT, addr_end TEXT, size INTEGER, thread_id INTEGER);"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS call (ins_id INTEGER, addr TEXT, name TEXT);"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS ins (bbl_id INTEGER, ip TEXT, dis TEXT, op TEXT);"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS mem (ins_id INTEGER, ip TEXT, type TEXT, addr TEXT, addr_end TEXT, size INTEGER, data TEXT, value TEXT);"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS thread (thread_id INTEGER, start_bbl_id INTEGER, exit_bbl_id INTEGER);"
        )

        self.cur.executemany(
            "INSERT INTO info VALUES (?, ?)",
            [
                ("TRACERGRIND_VERSION", "Qiling"),
                ("ARCH", str(ql.arch.type)),
                ("PROGRAM", ql.argv[0]),
                ("ARGS", "\x00".join(ql.argv)),
            ],
        )

    def setup(self):
        self.ins_id = 0
        self.bbl_id = 0

        def hook_block(ql: Qiling, address: int, size: int, *context: Any):
            self.cur.execute(
                "INSERT INTO bbl (addr, addr_end, size, thread_id) VALUES (?, ?, ?, ?);",
                [
                    hex(address),
                    hex(address + size - 1),
                    size,
                    ql.os.thread_management.cur_thread.id if ql.multithread else 0,
                ],
            )
            self.bbl_id += 1

        self.ql.hook_block(hook_block)

        def hook_read(
            ql: Qiling, access: int, address: int, size: int, value: int, *context: Any
        ):
            self.cur.execute(
                "INSERT INTO mem (ins_id, ip, type, addr, addr_end, size, data, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                [
                    self.ins_id,
                    hex(ql.arch.regs.arch_pc),
                    "R",
                    hex(address),
                    hex(address + size - 1),
                    size,
                    ql.mem.read(address, size).hex(),
                    hex(value),
                ],
            )

        self.ql.hook_mem_read(hook_read)

        def hook_write(
            ql: Qiling, access: int, address: int, size: int, value: int, *context: Any
        ):
            self.cur.execute(
                "INSERT INTO mem (ins_id, ip, type, addr, addr_end, size, data, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                [
                    self.ins_id,
                    hex(ql.arch.regs.arch_pc),
                    "W",
                    hex(address),
                    hex(address + size - 1),
                    size,
                    ql.mem.read(address, size).hex(),
                    hex(value),
                ],
            )

        self.ql.hook_mem_write(hook_write)

        def hook_code(ql: Qiling, address: int, size: int, *context: Any):
            code = ql.mem.read(address, size)
            md = ql.arch.disassembler
            dis = "\n".join(
                f"{insn.mnemonic:10s} {insn.op_str:s}"
                for insn in md.disasm(code, address)
            )

            self.cur.execute(
                "INSERT INTO ins (bbl_id, ip, dis, op) VALUES (?, ?, ?, ?);",
                [self.bbl_id, hex(address), dis, code.hex()],
            )
            self.ins_id += 1

        self.ql.hook_code(hook_code)

        self.threads = {}

        def hook_spawn(arg):
            old_free = arg.stop

            def hook_stop(*args, **kwargs):
                self.threads[arg.id] = self.bbl_id
                return old_free(*args, **kwargs)

            if arg.id not in self.threads:
                self.cur.execute(
                    "INSERT INTO thread (thread_id, start_bbl_id) VALUES (?, ?);",
                    [arg.id, self.bbl_id],
                )
                self.threads[arg.id] = None

            arg.stop = hook_stop

        if self.ql.multithread:

            old_setter = self.ql.os.__class__.__setattr__

            def hook_setter(self, name, value):
                if name == "thread_management":
                    # hook thread creation
                    old_add_thread = value.add_thread

                    def hook_thread_add(thread: QlThread):
                        thread.add_spawn_callback(hook_spawn)
                        return old_add_thread(thread)

                    value.add_thread = hook_thread_add

                return old_setter(self, name, value)

            self.ql.os.__class__.__setattr__ = hook_setter

        old_mapinfo = self.ql.mem.add_mapinfo

        def hook_mapinfo(
            mem_s: int, mem_e: int, mem_p: int, mem_info: str, is_mmio: bool = False
        ):
            self.cur.execute(
                "INSERT INTO lib (name, base, end) VALUES (?, ?, ?);",
                [mem_info, hex(mem_s), hex(mem_e)],
            )
            return old_mapinfo(mem_s, mem_e, mem_p, mem_info, is_mmio)

        self.ql.mem.add_mapinfo = hook_mapinfo

    def stop(self):
        for tid, bb_id in self.threads.items():
            self.cur.execute(
                "UPDATE thread SET exit_bbl_id=? WHERE thread_id=?;", [tid, bb_id]
            )
        self.con.commit()
        self.con.close()
