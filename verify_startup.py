#!/usr/bin/env python3
"""Run the real clipboard, UI, session and hook paths with an Android JNI fixture."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import *

BASE = 0x7000000000
HOST = BASE + 0x10000000
UI = BASE + 0x7dfe7b8
FLAGS = BASE + 0x75f9000
INPUT = HOST + 0x100000
OUTPUT = INPUT + 0x1000
JNI = HOST + 0x200000
VTABLE = JNI + 0x1000
HOOK_SLOT = HOST + 0x210000
HOOK_VECTOR = HOOK_SLOT + 0x1000
ORIGINAL = HOST + 0x220000
REPLACEMENT = ORIGINAL + 0x100
STACK = HOST + 0x2fff000
STOP = HOST + 0xff000


class Image:
    def __init__(self, path):
        self.u = u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
        u.mem_map(BASE, 0x9000000)
        u.mem_map(HOST, 0x3000000)
        with path.open('rb') as stream:
            elf = ELFFile(stream)
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    u.mem_write(BASE + segment['p_vaddr'], segment.data())
            symbols = list(elf.get_section_by_name('.dynsym').iter_symbols())
            self.imports = {}
            self.names = {}
            for symbol in symbols:
                if symbol.name and symbol['st_shndx'] == 'SHN_UNDEF':
                    address = HOST + 16 * len(self.imports)
                    self.imports[symbol.name] = address
                    self.names[address] = symbol.name
                    u.mem_write(address, bytes.fromhex('c0035fd6'))
            for section in ['.rela.dyn', '.rela.plt']:
                for relocation in elf.get_section_by_name(section).iter_relocations():
                    value = relocation['r_addend']
                    kind = relocation['r_info_type']
                    if kind == 1027:
                        value += BASE
                    elif kind in [257, 1025, 1026]:
                        symbol = symbols[relocation['r_info_sym']]
                        value += self.imports.get(symbol.name, BASE + symbol['st_value'])
                    else:
                        raise AssertionError(('relocation', kind))
                    u.mem_write(BASE + relocation['r_offset'], struct.pack('<Q', value & ((1 << 64) - 1)))
        u.reg_write(UC_ARM64_REG_TPIDR_EL0, HOST + 0x2f00000)
        u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
        u.hook_add(UC_HOOK_CODE, self.external, begin=HOST, end=HOST + 0x10000)
        u.hook_add(UC_HOOK_INTR, self.interrupt)
        self.next_allocation = HOST + 0x240000
        self.clipboard = '@Icon_Crack'
        self.clipboard_error = False
        self.snapshots = []
        self.actions = []
        self.clipboard_reads = 0
        for pc in [0x67eebc, 0x6810bc, 0x6811ec, 0x69b2d8, 0x69b380,
                   0x631378, 0x631a24, 0x631b98, 0x13cfc4, 0x13d1cc]:
            u.hook_add(UC_HOOK_CODE, self.platform, begin=BASE + pc, end=BASE + pc)
        methods = {0x98: 'PushLocalFrame', 0xa0: 'PopLocalFrame', 0xf8: 'GetObjectClass',
                   0x108: 'GetMethodID', 0x118: 'CallObjectMethodV', 0x538: 'NewStringUTF',
                   0x720: 'ExceptionCheck', 0x88: 'ExceptionClear',
                   0x520: 'GetStringLength', 0x6e0: 'GetStringRegion'}
        u.mem_write(JNI, struct.pack('<Q', VTABLE))
        for index, (offset, name) in enumerate(methods.items()):
            address = HOST + 0x8000 + index * 16
            self.names[address] = 'JNI:' + name
            u.mem_write(address, bytes.fromhex('c0035fd6'))
            u.mem_write(VTABLE + offset, struct.pack('<Q', address))

    def reg(self, n):
        return self.u.reg_read(UC_ARM64_REG_X0 + n)

    def ret(self, value=0):
        self.u.reg_write(UC_ARM64_REG_X0, value)
        self.u.reg_write(UC_ARM64_REG_PC, self.u.reg_read(UC_ARM64_REG_LR))

    def external(self, machine, pc, size, data):
        name = self.names[pc]
        a = [self.reg(n) for n in range(5)]
        if name.startswith('pthread_mutex_'):
            self.ret()
        elif name == 'clock_gettime':
            self.u.mem_write(a[1], struct.pack('<QQ', 1000, 123456)); self.ret()
        elif name in ['memcpy', 'memmove', '__memcpy_chk']:
            self.u.mem_write(a[0], bytes(self.u.mem_read(a[1], a[2]))); self.ret(a[0])
        elif name == 'memset':
            self.u.mem_write(a[0], bytes([a[1] & 255]) * a[2]); self.ret(a[0])
        elif name == '__system_property_get':
            self.u.mem_write(a[1], b'test-device\0'); self.ret(11)
        elif name == 'strlen':
            self.ret(len(bytes(self.u.mem_read(a[0], 4096)).split(b'\0')[0]))
        elif name.startswith('JNI:'):
            method = name[4:]
            if method in ['GetObjectClass', 'GetMethodID', 'CallObjectMethodV', 'NewStringUTF']:
                self.ret(JNI + 0x2000)
            elif method == 'GetStringLength':
                self.clipboard_reads += 1
                self.ret(len(self.clipboard))
            elif method == 'GetStringRegion':
                self.u.mem_write(a[4], self.clipboard[a[2]:a[2] + a[3]].encode('utf-16le')); self.ret()
            else:
                self.ret()
        else:
            raise AssertionError(('unexpected import', name))

    def interrupt(self, machine, number, data):
        assert number == 2 and self.u.reg_read(UC_ARM64_REG_X8) == 113
        self.u.mem_write(self.reg(1), struct.pack('<QQ', 1000, 123456))
        self.u.reg_write(UC_ARM64_REG_X0, 0)

    def platform(self, machine, pc, size, data):
        pc -= BASE
        if pc == 0x67eebc:
            self.snapshots.append(self.snapshot())
            if self.actions:
                self.actions.pop(0)(self)
            else:
                self.u.mem_write(FLAGS + 0x6b0, b'\1')
            self.ret()
        elif pc == 0x6810bc:
            self.ret(1)
        elif pc == 0x6811ec:
            self.u.mem_write(self.reg(0), b'\1'); self.ret()
        elif pc == 0x69b2d8:
            address = self.next_allocation
            self.next_allocation += (self.reg(0) + 15) & ~15
            self.ret(address)
        elif pc == 0x69b380:
            self.ret()
        elif pc in [0x13cfc4, 0x13d1cc]:
            self.u.mem_read(self.reg(1), self.reg(2)); self.ret(1)
        elif pc == 0x631378:
            self.u.mem_write(self.reg(0), struct.pack('<Q', JNI)); self.ret(3 if self.clipboard_error else 0)
        elif pc == 0x631a24:
            self.u.mem_write(self.reg(0), struct.pack('<QQQ', 0, JNI, 0)); self.ret()
        elif pc == 0x631b98:
            self.ret(JNI + 0x2000)

    def call(self, pc, *values, out=None):
        self.u.reg_write(UC_ARM64_REG_SP, STACK)
        self.u.reg_write(UC_ARM64_REG_LR, STOP)
        for n, value in enumerate(values):
            self.u.reg_write(UC_ARM64_REG_X0 + n, value)
        if out is not None:
            self.u.reg_write(UC_ARM64_REG_X8, out)
        self.u.emu_start(BASE + pc, STOP, count=3_000_000)
        assert self.u.reg_read(UC_ARM64_REG_PC) == STOP, hex(self.u.reg_read(UC_ARM64_REG_PC))
        return self.reg(0)

    def integer(self, address, size=4):
        return int.from_bytes(self.u.mem_read(address, size), 'little')

    def string(self, text):
        value = text.encode()
        if len(value) < 23:
            return (bytes([len(value) * 2]) + value + b'\0').ljust(24, b'\0')
        address = self.next_allocation
        self.next_allocation += (len(value) + 32) & ~15
        self.u.mem_write(address, value + b'\0')
        return struct.pack('<QQQ', ((len(value) + 16) & ~15) | 1, len(value), address)

    def text(self, address):
        first = self.integer(address, 1)
        length = self.integer(address + 8, 8) if first & 1 else first >> 1
        pointer = self.integer(address + 16, 8) if first & 1 else address + 1
        return bytes(self.u.mem_read(pointer, length)).decode()

    def reset(self):
        self.u.mem_write(UI, bytes(0x240))
        self.u.mem_write(FLAGS + 0x6b0, bytes(0x200))
        self.u.mem_write(FLAGS + 0x6b4, b'\1')
        self.u.mem_write(BASE + 0x75d9558, b'\1')
        self.u.mem_write(BASE + 0x7dfeca0, b'\0')
        self.u.mem_write(BASE + 0x7fe1410, bytes(8))
        self.u.mem_write(BASE + 0x8291d78, bytes(0x40))
        self.u.mem_write(HOOK_SLOT, struct.pack('<Q', ORIGINAL))
        self.u.mem_write(HOOK_VECTOR, struct.pack('<QQQQ', HOOK_SLOT, ORIGINAL, REPLACEMENT, 0))
        self.u.mem_write(BASE + 0x75d67a8, struct.pack('<QQQ', HOOK_VECTOR, HOOK_VECTOR + 32, HOOK_VECTOR + 32))
        self.snapshots = []
        self.actions = []
        self.clipboard_error = False
        self.clipboard_reads = 0
        self.call(0x1a090c, UI)

    def submit(self, text):
        self.u.mem_write(INPUT, self.string(text))
        self.call(0x1a0ee4, UI, INPUT)

    def snapshot(self):
        return {'ui_state': self.integer(UI + 0x28), 'clipboard_pending': self.integer(UI + 0x90),
                'clipboard_result': self.text(UI + 0x60), 'clipboard_error': self.text(UI + 0x78),
                'phase': self.integer(FLAGS + 0x6cc), 'hooks_enabled': self.integer(BASE + 0x7fe1414, 1),
                'bootstrap_binding_ready': self.integer(BASE + 0x8291db0, 1),
                'hook_slot': self.integer(HOOK_SLOT, 8)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('payload', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    regressions = {}
    if args.baseline:
        old = Image(args.baseline)
        old.reset(); old.submit('@Icon_Crack'); old.call(0x169a00)
        regressions['old_success_did_not_enable_original_hooks'] = old.snapshots[0]['hooks_enabled'] == 0
        regressions['old_success_did_not_initialize_startup_binding'] = old.snapshots[0]['bootstrap_binding_ready'] == 0
        old.reset(); old.u.mem_write(UI + 0x90, struct.pack('<I', 1)); old.call(0x169a00)
        regressions['old_paste_request_never_serviced'] = old.snapshots[0]['clipboard_pending'] == 1 and old.clipboard_reads == 0
        assert all(regressions.values()), regressions
        del old
    image = Image(args.payload)
    cases = [('@Icon_Crack', True), (' \t@Icon_Crack\r\n', True), (' ' * 32 + '@Icon_Crack' + '\n', True),
             ('@icon_crack', False), ('@Icon_CracK', False), ('', False), ('wrong-key', False)]
    for text, valid in cases:
        image.reset(); image.submit(text); image.actions = [lambda i: None, lambda i: None]
        image.call(0x169a00)
        assert len(image.snapshots) == 3
        for snapshot in image.snapshots:
            assert snapshot['ui_state'] == (4 if valid else 3), (text, snapshot)
            assert snapshot['phase'] == (6 if valid else 0), (text, snapshot)
            assert snapshot['hooks_enabled'] == int(valid), (text, snapshot)
            assert snapshot['bootstrap_binding_ready'] == int(valid), (text, snapshot)
            assert snapshot['hook_slot'] == (REPLACEMENT if valid else ORIGINAL)
        assert image.integer(HOOK_SLOT, 8) == ORIGINAL
        assert image.integer(BASE + 0x7fe1414, 1) == 0
        assert image.call(0x636668) == int(valid)

    clipboard_cases = [('@Icon_Crack', True), (' \t@Icon_Crack\r\n', True), ('ZAPKFREE-EXAMPLE1', False), ('wrong-key', False)]
    for text, valid in clipboard_cases:
        image.reset(); image.clipboard = text
        image.u.mem_write(UI + 0x90, struct.pack('<I', 1))
        image.call(0x169a00)
        snapshot = image.snapshots[0]
        assert image.clipboard_reads > 0 and snapshot['clipboard_pending'] == 0, snapshot
        assert snapshot['clipboard_result'] == ('@Icon_Crack' if valid else ''), snapshot
        assert bool(snapshot['clipboard_error']) == (not valid), snapshot
    image.reset(); image.clipboard_error = True
    image.u.mem_write(UI + 0x90, struct.pack('<I', 1)); image.call(0x169a00)
    assert image.snapshots[0]['clipboard_pending'] == 0
    assert image.snapshots[0]['clipboard_error'] == 'Clipboard unavailable'

    # Closing/hiding the login UI must not revoke the established service session.
    image.reset(); image.submit('@Icon_Crack'); image.call(0x169a00)
    image.u.mem_write(FLAGS + 0x6b0, b'\0')
    image.u.mem_write(FLAGS + 0x6cc, struct.pack('<I', 6))
    image.u.mem_write(UI + 0x28, bytes(4))
    gates = [0x16a944, 0x16aef0, 0x16af60, 0x16afd0, 0x16b040]
    for pc in gates:
        assert image.call(pc) == 1, hex(pc)
    image.u.mem_write(INPUT, struct.pack('<Q', 1)); assert image.call(0x16ab84, INPUT) == 1
    image.u.mem_write(INPUT, struct.pack('<Q', 2)); assert image.call(0x16ab84, INPUT) == 0
    image.u.mem_write(FLAGS + 0x6b0, b'\1')
    for pc in gates:
        assert image.call(pc) == 0
    contacts = []
    def contact_draw(machine, pc, size, data):
        contacts.append(bytes(image.u.mem_read(image.reg(3), 64)).split(b'\0')[0].decode())
        image.ret()
    image.u.hook_add(UC_HOOK_CODE, contact_draw, begin=BASE + 0x536f60, end=BASE + 0x536f60)
    image.call(0x536c88)
    assert contacts == ['https://t.me/Icon_Crack', 'https://t.me/Icon_Crack']
    for address in [0x828a688, 0x828a6c8]:
        assert image.integer(BASE + address, 1) == 1
    report = {'payload_sha256': hashlib.sha256(args.payload.read_bytes()).hexdigest(),
              'baseline_regressions_reproduced': regressions, 'manual_input_cases': len(cases),
              'original_android_clipboard_path_cases': len(clipboard_cases),
              'clipboard_failure_finishes_pending_request': True,
              'real_original_hook_switch_and_memory_updates_executed': True,
              'original_session_binding_initializer_and_final_startup_check_executed': True,
              'success_remains_active_across_three_worker_iterations': True,
              'original_hooks_restored_on_shutdown': True,
              'session_survives_login_ui_closing': True,
              'original_public_gates_tested': len(gates), 'wrong_stored_token_rejected': True,
              'original_contact_initializer_and_decoder_executed': True,
              'contact_urls': contacts, 'contact_buffer_guard_bytes_preserved': True,
              'aslr_base': hex(BASE), 'native_network_calls': 0, 'android_device_tested': False,
              'stubs': ['Android JNI environment/context and Java clipboard responses',
                        'pthread mutexes', 'memory allocation/free', 'clock and sleep',
                        'C++ static guards', 'OS memory accessibility checks',
                        'Android system properties and libc string length'],
              'limits': 'Executes native clipboard retrieval, normalization, UI state, session and hook transitions; Android rendering and full game startup require a device.'}
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
