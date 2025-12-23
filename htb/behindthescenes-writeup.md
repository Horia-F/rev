# Behind the Scenes – Reverse Engineering Writeup

## Challenge Overview

This challenge is a Linux x86-64 ELF binary that appears to do *nothing*:
- It prints no output
- It always exits with code `0`
- `strace` and `ltrace show almost no useful behavior`
- The binary deliberately triggers `SIGILL` using illegal instructions (`UD2`)

The goal is to recover the password that reveals the flag.

---

## Initial Recon

```bash
file behindthescenes
```

Output:
```
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Key observations:
- PIE binary
- Not stripped → symbols available
- Uses SIGILL handling → obfuscation

---

## Anti-Disassembly Trick (SIGILL + UD2)

The binary installs a custom SIGILL handler:

```c
void segill_sigaction(undefined8 a, undefined8 b, long ctx) {
    *(long *)(ctx + 0xa8) += 2;
}
```

### Explanation

- `UD2` (`0F 0B`) is a 2-byte illegal instruction
- Triggering it raises `SIGILL`
- The handler advances RIP by 2 bytes
- Execution resumes after the illegal instruction

This breaks linear disassembly and confuses static analysis.

---

## Removing the Obfuscation

All `UD2` instructions were patched to `NOP NOP`.

```bash
cp behindthescenes behindthescenes.patched
```

```python
data = bytearray(open("behindthescenes.patched","rb").read())
while b"\x0f\x0b" in data:
    i = data.find(b"\x0f\x0b")
    data[i:i+2] = b"\x90\x90"
open("behindthescenes.patched","wb").write(data)
```

---

## Recovered Logic

```c
if (argc == 2) {
    if (strlen(argv[1]) == 12) {
        if (!strncmp(argv[1],     "Itz", 3) &&
            !strncmp(argv[1] + 3, "_0n", 3) &&
            !strncmp(argv[1] + 6, "Ly_", 3) &&
            !strncmp(argv[1] + 9, "UD2", 3)) {

            printf("> HTB{%s}\n", argv[1]);
        }
    }
}
```

---

## Password

```
Itz_0nLy_UD2
```

---

## Flag

```
HTB{Itz_0nLy_UD2}
```

---

## Key Takeaways

- SIGILL + UD2 is a classic anti-disassembly trick
- Dynamic analysis is essential
- Obfuscation often hides very simple logic
