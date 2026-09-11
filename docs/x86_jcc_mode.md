# Operand-size-prefixed near Jcc in 64-bit mode

`CS_OPT_X86_JCC_MODE` selects how the x86 decoder handles the operand-size
prefix (`66`) on near conditional branches (`0F 80` through `0F 8F`) in
64-bit mode. The setting belongs to the Capstone handle; it is independent
of the host CPU and the output syntax.

| Value | Behavior with `66`, without an effective `REX.W` |
| --- | --- |
| `CS_OPT_X86_JCC_DEFAULT` | Preserve legacy behavior: `JO/JNO` consume rel16; the other near Jcc consume rel32. Existing target and operand details are preserved too. |
| `CS_OPT_X86_JCC_INTEL` | All near Jcc consume rel32 and use a 64-bit target. |
| `CS_OPT_X86_JCC_AMD` | All near Jcc consume rel16 and truncate the target to 16 bits. |

New handles use `DEFAULT`. Explicitly selecting `DEFAULT` restores that
behavior. In the explicit modes, an effective `REX.W` takes precedence over
`66` and selects rel32. Prefix order matters: a legacy prefix after a REX
prefix makes that REX ineffective.

This option does not select a complete CPU model. It leaves `CALL`, `JMP`,
short Jcc, instructions without `66`, and 16/32-bit decoding unchanged.
Invalid values and non-x86 handles return `CS_ERR_OPTION`.

## C

After opening an x86 handle in `CS_MODE_64`, select a policy with:

```c
cs_err err = cs_option(handle, CS_OPT_X86_JCC_MODE, CS_OPT_X86_JCC_INTEL);
/* Check err before using the handle. */
```

Use `CS_OPT_X86_JCC_AMD` to select the AMD interpretation, or
`CS_OPT_X86_JCC_DEFAULT` to restore compatibility behavior.

## Python

```python
from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_64,
    CS_OPT_X86_JCC_INTEL, CS_OPT_X86_JCC_AMD,
)

code = bytes.fromhex("66 0f 80 ce fa a5 d8")
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for name, mode in (("Intel", CS_OPT_X86_JCC_INTEL), ("AMD", CS_OPT_X86_JCC_AMD)):
    md.x86_jcc_mode = mode
    print(name)
    for insn in md.disasm(code, 0):
        print(insn.address, insn.size, insn.imm_size, insn.mnemonic, insn.op_str)
```

Intel mode consumes all seven bytes as one branch. AMD mode consumes five
bytes as the branch, then decodes `A5` as a separate string move. The final
`D8` is incomplete, so normal Capstone iteration stops there.

`encoding.imm_size` (Python: `insn.imm_size`) reports the encoded relative
immediate width: 4 for rel32, 2 for rel16. In explicit modes, the prefixed
branch operand's `size` reports the target width: 8 or 2, respectively.

## Tests

```sh
cmake -S . -B build-jcc -DCMAKE_BUILD_TYPE=Debug \
    -DCAPSTONE_BUILD_CSTEST=ON -DCAPSTONE_BUILD_SHARED_LIBS=ON
cmake --build build-jcc -j4
ctest --test-dir build-jcc -R unit_x86_jcc_mode --output-on-failure
build-jcc/suite/cstest/cstest tests/features/x86_jcc_mode.yaml
LIBCAPSTONE_PATH="$PWD/build-jcc" PYTHONPATH="$PWD/bindings/python" \
    python -m unittest discover -s bindings/python/tests -p test_x86_jcc_mode.py -v
```

The C test checks every condition, signed offsets, target wraparound,
prefix order, Intel/AT&T output, instruction boundaries, option validation,
handle isolation, resetting the policy, and unaffected instructions/modes.
The Python test covers binding state, the two interpretations, and decoding
without detail output. Neither test executes the input bytes on the host CPU.
