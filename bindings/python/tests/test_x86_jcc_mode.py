import unittest

from capstone import (
    Cs,
    CsError,
    CS_ARCH_X86,
    CS_ERR_OPTION,
    CS_MODE_64,
    CS_OPT_SYNTAX_ATT,
    CS_OPT_SYNTAX_INTEL,
    CS_OPT_X86_JCC_MODE,
    CS_OPT_X86_JCC_DEFAULT,
    CS_OPT_X86_JCC_INTEL,
    CS_OPT_X86_JCC_AMD,
)
from capstone.x86 import X86_INS_MOVSD


class TestX86JccMode(unittest.TestCase):
    def setUp(self):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

    def test_all_conditions(self):
        for syntax in (CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT):
            self.cs.syntax = syntax
            for mode in (CS_OPT_X86_JCC_INTEL, CS_OPT_X86_JCC_AMD):
                self.cs.x86_jcc_mode = mode
                for opcode in range(0x80, 0x90):
                    with self.subTest(syntax=syntax, mode=mode, opcode=opcode):
                        code = bytes([0x66, 0x0F, opcode, 0xCE, 0xFA, 0xA5, 0xD8])
                        insns = list(self.cs.disasm(code, 0))
                        branch = insns[0]
                        if mode == CS_OPT_X86_JCC_AMD:
                            self.assertEqual(len(insns), 2)
                            self.assertEqual(branch.size, 5)
                            self.assertEqual(branch.imm_size, 2)
                            self.assertEqual(branch.operands[0].size, 2)
                            self.assertEqual(branch.operands[0].imm, 0xFAD3)
                            self.assertEqual(insns[1].id, X86_INS_MOVSD)
                            self.assertEqual(insns[1].address, 5)
                        else:
                            self.assertEqual(len(insns), 1)
                            self.assertEqual(branch.size, 7)
                            self.assertEqual(branch.imm_size, 4)
                            self.assertEqual(branch.operands[0].size, 8)
                            self.assertEqual(
                                branch.operands[0].imm & ((1 << 64) - 1),
                                0xFFFFFFFFD8A5FAD5,
                            )

    def test_default_reset_and_handle_isolation(self):
        other = Cs(CS_ARCH_X86, CS_MODE_64)
        code = bytes.fromhex("66 0f 80 ce fa a5 d8")
        self.assertEqual(self.cs.x86_jcc_mode, CS_OPT_X86_JCC_DEFAULT)
        self.cs.option(CS_OPT_X86_JCC_MODE, CS_OPT_X86_JCC_INTEL)
        self.assertEqual(self.cs.x86_jcc_mode, CS_OPT_X86_JCC_INTEL)
        self.assertEqual(next(self.cs.disasm(code, 0)).size, 7)
        self.assertEqual(next(other.disasm(code, 0)).size, 5)
        self.cs.x86_jcc_mode = CS_OPT_X86_JCC_DEFAULT
        self.assertEqual(next(self.cs.disasm(code, 0)).size, 5)
        self.assertEqual(next(self.cs.disasm(code, 0)).operands[0].size, 4)

    def test_invalid_option_preserves_state(self):
        self.cs.x86_jcc_mode = CS_OPT_X86_JCC_AMD
        for invalid in (3, -1):
            with self.assertRaises(CsError) as raised:
                self.cs.x86_jcc_mode = invalid
            self.assertEqual(raised.exception.errno, CS_ERR_OPTION)
            self.assertEqual(self.cs.x86_jcc_mode, CS_OPT_X86_JCC_AMD)
        branch = next(self.cs.disasm(bytes.fromhex("66 0f 80 ce fa"), 0))
        self.assertEqual(branch.operands[0].imm, 0xFAD3)

    def test_detail_disabled(self):
        self.cs.detail = False
        self.cs.x86_jcc_mode = CS_OPT_X86_JCC_AMD
        code = bytes.fromhex("66 0f 80 ce fa a5 d8")
        branch = next(self.cs.disasm(code, 0x123450000))
        self.assertEqual(branch.size, 5)
        self.assertEqual(branch.op_str, "0xfad3")


if __name__ == "__main__":
    unittest.main()
