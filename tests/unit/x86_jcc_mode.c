#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keep checks active in Release builds, too. */
#define CHECK(expr) \
	do { \
		if (!(expr)) { \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, \
				#expr); \
			exit(1); \
		} \
	} while (0)

static const unsigned int ids[] = {
	X86_INS_JO, X86_INS_JNO, X86_INS_JB,  X86_INS_JAE,
	X86_INS_JE, X86_INS_JNE, X86_INS_JBE, X86_INS_JA,
	X86_INS_JS, X86_INS_JNS, X86_INS_JP,  X86_INS_JNP,
	X86_INS_JL, X86_INS_JGE, X86_INS_JLE, X86_INS_JG,
};

static csh open_x86(cs_mode mode)
{
	csh handle;
	CHECK(cs_open(CS_ARCH_X86, mode, &handle) == CS_ERR_OK);
	CHECK(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
	return handle;
}

static void check_branch(csh handle, const uint8_t *code, size_t code_size,
			 uint64_t address, unsigned int id, size_t length,
			 uint8_t imm_offset, uint8_t imm_size,
			 uint8_t operand_size, uint64_t target)
{
	cs_insn *insn;
	size_t count = cs_disasm(handle, code, code_size, address, 1, &insn);
	CHECK(count == 1);
	CHECK(insn->id == id);
	CHECK(insn->size == length);
	CHECK(insn->detail->x86.encoding.imm_offset == imm_offset);
	CHECK(insn->detail->x86.encoding.imm_size == imm_size);
	CHECK(insn->detail->x86.op_count == 1);
	CHECK(insn->detail->x86.operands[0].type == X86_OP_IMM);
	CHECK(insn->detail->x86.operands[0].size == operand_size);
	CHECK((uint64_t)insn->detail->x86.operands[0].imm == target);
	cs_free(insn, count);
}

static void check_explicit_encoding(csh handle, uint8_t *code, uint8_t offset,
				    bool rel16, unsigned int id)
{
	static const uint64_t addresses[] = {
		0,
		0xfffe,
		UINT64_C(0x123450000),
		UINT64_MAX - 2,
	};
	static const uint32_t displacements[] = {
		0xd8a5face,
		1,
		0x80008000,
		0xffffffff,
	};
	uint8_t width = rel16 ? 2 : 4;
	for (size_t d = 0; d < sizeof(displacements) / sizeof(displacements[0]);
	     d++) {
		uint32_t displacement = displacements[d];
		for (unsigned int b = 0; b < 4; b++)
			code[offset + b] = displacement >> (8 * b);
		for (size_t a = 0; a < sizeof(addresses) / sizeof(addresses[0]);
		     a++) {
			uint64_t target = addresses[a] + offset + width;
			if (rel16)
				target = (target + (displacement & 0xffff)) &
					 0xffff;
			else
				target += (uint64_t)(int64_t)(int32_t)
					displacement;
			check_branch(handle, code, offset + 4, addresses[a], id,
				     offset + width, offset, width,
				     rel16 ? 2 : 8, target);
		}
	}
}

static void test_explicit_modes(csh handle)
{
	static const struct {
		uint8_t bytes[2];
		uint8_t size;
		bool rex_w;
	} prefixes[] = {
		{ { 0x66 }, 1, false },	      { { 0x66, 0x48 }, 2, true },
		{ { 0x48, 0x66 }, 2, false }, { { 0x66, 0x40 }, 2, false },
		{ { 0x66, 0x67 }, 2, false }, { { 0x66, 0x66 }, 2, false },
	};
	for (size_t policy = CS_OPT_X86_JCC_INTEL; policy <= CS_OPT_X86_JCC_AMD;
	     policy++) {
		CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, policy) ==
		      CS_ERR_OK);
		for (unsigned int cc = 0; cc < 16; cc++) {
			for (size_t p = 0;
			     p < sizeof(prefixes) / sizeof(prefixes[0]); p++) {
				uint8_t code[8];
				uint8_t offset = prefixes[p].size + 2;
				bool rel16 = policy == CS_OPT_X86_JCC_AMD &&
					     !prefixes[p].rex_w;
				memcpy(code, prefixes[p].bytes,
				       prefixes[p].size);
				code[offset - 2] = 0x0f;
				code[offset - 1] = 0x80 + cc;
				check_explicit_encoding(handle, code, offset,
							rel16, ids[cc]);
			}
		}
	}
}

static void test_default(csh handle)
{
	/* Preserve legacy instruction lengths, targets, and operand sizes. */
	for (unsigned int cc = 0; cc < 16; cc++) {
		const uint8_t code[] = { 0x66, 0x0f, 0x80 + cc, 0xce,
					 0xfa, 0xa5, 0xd8 };
		check_branch(handle, code, sizeof(code), 0, ids[cc],
			     cc < 2 ? 5 : 7, 3, cc < 2 ? 2 : 4, 4,
			     cc < 2 ? UINT64_C(0xfffffffffffffad3) :
				      UINT64_C(0xffffffffd8a5fad5));
	}
}

static void test_stream_and_options(csh handle)
{
	const uint8_t code[] = { 0x66, 0x0f, 0x80, 0xce, 0xfa, 0xa5, 0xd8 };
	cs_insn *insn;
	csh other = open_x86(CS_MODE_64);
	CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, CS_OPT_X86_JCC_AMD) ==
	      CS_ERR_OK);
	/* Changing bitness must preserve the selected Jcc policy. */
	CHECK(cs_option(handle, CS_OPT_MODE, CS_MODE_32) == CS_ERR_OK);
	check_branch(handle, code, sizeof(code), 0, X86_INS_JO, 5, 3, 2, 2,
		     0xfad3);
	CHECK(cs_option(handle, CS_OPT_MODE, CS_MODE_64) == CS_ERR_OK);
	check_branch(handle, code, sizeof(code), 0, X86_INS_JO, 5, 3, 2, 2,
		     0xfad3);
	CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, 3) == CS_ERR_OPTION);
	CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, (size_t)-1) ==
	      CS_ERR_OPTION);
	/* Rejected values must not replace AMD mode. */
	size_t count = cs_disasm(handle, code, sizeof(code), 0, 0, &insn);
	CHECK(count == 2);
	CHECK(insn[0].size == 5);
	CHECK(insn[1].address == 5);
	CHECK(insn[1].id == X86_INS_MOVSD);
	CHECK(insn[1].size == 1);
	cs_free(insn, count);

	/* Iterative decoding must consume exactly the same bytes. */
	insn = cs_malloc(handle);
	CHECK(insn != NULL);
	const uint8_t *cursor = code;
	size_t remaining = sizeof(code);
	uint64_t address = 0;
	CHECK(cs_disasm_iter(handle, &cursor, &remaining, &address, insn));
	CHECK(address == 5 && remaining == 2 && cursor == code + 5);
	CHECK(cs_disasm_iter(handle, &cursor, &remaining, &address, insn));
	CHECK(address == 6 && remaining == 1 && insn->id == X86_INS_MOVSD);
	CHECK(!cs_disasm_iter(handle, &cursor, &remaining, &address, insn));
	cs_free(insn, 1);

	CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, CS_OPT_X86_JCC_INTEL) ==
	      CS_ERR_OK);
	count = cs_disasm(handle, code, sizeof(code), 0, 0, &insn);
	CHECK(count == 1 && insn[0].size == 7);
	cs_free(insn, count);
	/* A rel32 instruction with only two immediate bytes is incomplete. */
	CHECK(cs_disasm(handle, code, 5, 0, 1, &insn) == 0);
	test_default(other);
	CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, CS_OPT_X86_JCC_DEFAULT) ==
	      CS_ERR_OK);
	test_default(handle);
	CHECK(cs_close(&other) == CS_ERR_OK);
}

static void check_unchanged(csh reference, csh handle, const uint8_t *code,
			    size_t size)
{
	cs_insn *before, *after;
	size_t n = cs_disasm(reference, code, size, 0x12340000, 1, &before);
	size_t m = cs_disasm(handle, code, size, 0x12340000, 1, &after);
	CHECK(n == m);
	if (n == 0) {
		/* Some instructions in the test corpus are unavailable in X86-reduce. */
		CHECK(cs_support(CS_SUPPORT_X86_REDUCE));
		return;
	}
	CHECK(n == 1);
	CHECK(before->id == after->id && before->size == after->size);
	CHECK(strcmp(before->mnemonic, after->mnemonic) == 0);
	CHECK(strcmp(before->op_str, after->op_str) == 0);
	CHECK(memcmp(&before->detail->x86, &after->detail->x86,
		     sizeof(cs_x86)) == 0);
	cs_free(before, n);
	cs_free(after, m);
}

static void test_scope(void)
{
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
		csh reference = open_x86(modes[m]);
		csh handle = open_x86(modes[m]);
		for (size_t policy = CS_OPT_X86_JCC_INTEL;
		     policy <= CS_OPT_X86_JCC_AMD; policy++) {
			CHECK(cs_option(handle, CS_OPT_X86_JCC_MODE, policy) ==
			      CS_ERR_OK);
			for (unsigned int cc = 0; cc < 16; cc++) {
				const uint8_t near[] = { 0x66, 0x0f, 0x80 + cc,
							 0xce, 0xfa, 0xa5,
							 0xd8 };
				const uint8_t short_jcc[] = { 0x66, 0x70 + cc,
							      0xce };
				if (modes[m] != CS_MODE_64)
					check_unchanged(reference, handle, near,
							sizeof(near));
				check_unchanged(reference, handle, near + 1,
						sizeof(near) - 1);
				check_unchanged(reference, handle, short_jcc,
						sizeof(short_jcc));
			}
			const uint8_t others[][7] = {
				{ 0x66, 0xe8, 0xce, 0xfa, 0xa5, 0xd8 },
				{ 0x66, 0xe9, 0xce, 0xfa, 0xa5, 0xd8 },
				{ 0x66, 0xc3 },
				{ 0x66, 0x89, 0xc0 },
				{ 0x66, 0x0f, 0xe8, 0xc0 },
			};
			for (size_t i = 0;
			     i < sizeof(others) / sizeof(others[0]); i++)
				check_unchanged(reference, handle, others[i],
						sizeof(others[i]));
		}
		CHECK(cs_close(&reference) == CS_ERR_OK);
		CHECK(cs_close(&handle) == CS_ERR_OK);
	}
	/* Reject the architecture-specific option on other available targets. */
	if (cs_support(CS_ARCH_ARM)) {
		csh arm;
		CHECK(cs_open(CS_ARCH_ARM, CS_MODE_ARM, &arm) == CS_ERR_OK);
		CHECK(cs_option(arm, CS_OPT_X86_JCC_MODE,
				CS_OPT_X86_JCC_INTEL) == CS_ERR_OPTION);
		CHECK(cs_close(&arm) == CS_ERR_OK);
	}
}

int main(void)
{
	csh handle = open_x86(CS_MODE_64);
	test_default(handle);
	test_explicit_modes(handle);
	test_stream_and_options(handle);
	cs_err err = cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	if (err == CS_ERR_OK) {
		test_default(handle);
		test_explicit_modes(handle);
		test_stream_and_options(handle);
	} else {
		CHECK(err == (cs_support(CS_SUPPORT_DIET) ? CS_ERR_DIET :
							    CS_ERR_X86_ATT));
	}
	CHECK(cs_close(&handle) == CS_ERR_OK);
	test_scope();
	puts("x86 Jcc modes: passed");
	return 0;
}
