# 🪦 Grave Robber — Reverse Engineering Writeup

> Goal: make the program print the success message / flag by creating a specific **nested directory chain** that the binary checks with `stat()`.

---

## 1) What the binary does

Running `./robber` initially prints:

```
We took a wrong turning!
```

Using `strace` shows why: it checks for a directory path and exits as soon as a required directory is missing.

Example (your trace):

- First run (no `H/` directory):
  - `newfstatat(..., "H/", ...) = -1 ENOENT`
  - prints: `We took a wrong turning!`

- After you create `H/`, the next run checks deeper:
  - `newfstatat(..., "H/T/", ...) = -1 ENOENT`
  - prints: `We took a wrong turning!`

So the program is effectively revealing the “next letter” of the path it expects: each run tells you the next missing directory in the chain.

---

## 2) Static analysis (decompiled main)

The decompiled `main()` confirms this behavior. The key points:

- It builds a string in `local_58` that looks like:

  ```
  <char0>/
  <char0>/<char1>/
  <char0>/<char1>/<char2>/
  ...
  ```

- It calls `stat()` on that progressively-growing path.
- If `stat()` fails at any stage, it prints “wrong turning” and exits.
- If it completes all checks, it prints the success message.

Here is the decompiled function you provided (kept as-is, only wrapped in a Markdown code block):

```c
undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  uint local_ec;
  stat local_e8;
  char local_58 [72];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_58[0] = '\0';
  local_58[1] = '\0';
  local_58[2] = '\0';
  local_58[3] = '\0';
  local_58[4] = '\0';
  local_58[5] = '\0';
  local_58[6] = '\0';
  local_58[7] = '\0';
  local_58[8] = '\0';
  local_58[9] = '\0';
  local_58[10] = '\0';
  local_58[0xb] = '\0';
  local_58[0xc] = '\0';
  local_58[0xd] = '\0';
  local_58[0xe] = '\0';
  local_58[0xf] = '\0';
  local_58[0x10] = '\0';
  local_58[0x11] = '\0';
  local_58[0x12] = '\0';
  local_58[0x13] = '\0';
  local_58[0x14] = '\0';
  local_58[0x15] = '\0';
  local_58[0x16] = '\0';
  local_58[0x17] = '\0';
  local_58[0x18] = '\0';
  local_58[0x19] = '\0';
  local_58[0x1a] = '\0';
  local_58[0x1b] = '\0';
  local_58[0x1c] = '\0';
  local_58[0x1d] = '\0';
  local_58[0x1e] = '\0';
  local_58[0x1f] = '\0';
  local_58[0x20] = '\0';
  local_58[0x21] = '\0';
  local_58[0x22] = '\0';
  local_58[0x23] = '\0';
  local_58[0x24] = '\0';
  local_58[0x25] = '\0';
  local_58[0x26] = '\0';
  local_58[0x27] = '\0';
  local_58[0x28] = '\0';
  local_58[0x29] = '\0';
  local_58[0x2a] = '\0';
  local_58[0x2b] = '\0';
  local_58[0x2c] = '\0';
  local_58[0x2d] = '\0';
  local_58[0x2e] = '\0';
  local_58[0x2f] = '\0';
  local_58[0x30] = '\0';
  local_58[0x31] = '\0';
  local_58[0x32] = '\0';
  local_58[0x33] = '\0';
  local_58[0x34] = '\0';
  local_58[0x35] = '\0';
  local_58[0x36] = '\0';
  local_58[0x37] = '\0';
  local_58[0x38] = '\0';
  local_58[0x39] = '\0';
  local_58[0x3a] = '\0';
  local_58[0x3b] = '\0';
  local_58[0x3c] = '\0';
  local_58[0x3d] = '\0';
  local_58[0x3e] = '\0';
  local_58[0x3f] = '\0';
  local_58[0x40] = '\0';
  local_58[0x41] = '\0';
  local_58[0x42] = '\0';
  local_58[0x43] = '\0';
  local_ec = 0;
  do {
    if (0x1f < local_ec) {
      puts("We found the treasure! (I hope it\'s not cursed)");
      uVar2 = 0;
LAB_00101256:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar2;
    }
    local_58[(int)(local_ec * 2)] = (char)*(undefined4 *)(parts + (long)(int)local_ec * 4);
    local_58[(int)(local_ec * 2 + 1)] = '/';
    iVar1 = stat(local_58,&local_e8);
    if (iVar1 != 0) {
      puts("We took a wrong turning!");
      uVar2 = 1;
      goto LAB_00101256;
    }
    local_ec = local_ec + 1;
  } while( true );
}
```

### What matters in this code

- `parts` is an array of 32-bit values (one per character).
- Each loop iteration copies one character into the path buffer:
  - `local_58[local_ec*2] = parts[local_ec]`
  - `local_58[local_ec*2+1] = '/'`
- That creates a path like: `H/`, then `H/T/`, then `H/T/B/`, etc.
- It calls `stat(path, &st)`:
  - If `stat() != 0` → print “wrong turning” and exit.
  - After 32 iterations (`local_ec` from 0 to 31) → print success.

So the “flag” is effectively the sequence of characters stored in `parts[]` (32 characters), but you don’t have to extract it statically — you can recover it dynamically by creating the directories as the program asks for them.

---

## 3) Manual solve method (the intended feel)

1. Run `./robber` (or `strace ./robber`).
2. Observe the missing path it tries to `stat()`, e.g. `H/` or `H/T/`.
3. Create that directory.
4. Re-run the program.
5. Repeat until the program finally prints the success message and/or flag.

This works because the program exits at the first missing directory, effectively leaking the next character of the chain.

---

## 4) Automated solve (script)

Below is a script that:
- runs the binary under `strace`
- finds the first `ENOENT` path (`newfstatat(..., "X/Y/Z/", ...) = -1 ENOENT`)
- creates that directory
- repeats until the program prints the success output / flag

Save as `solve.py`:

```python
#!/usr/bin/env python3
import os
import re
import subprocess
import sys

BIN = "./robber"

# Matches: newfstatat(AT_FDCWD, "H/T/", ..., 0) = -1 ENOENT ...
RE_MISSING = re.compile(
    r'newfstatat\\(AT_FDCWD,\\s*"([^"]+)"[^)]*\\)\\s*=\\s*-1\\s+ENOENT'
)

def run_strace():
    p = subprocess.run(
        ["strace", "-qq", "-f", "-e", "trace=newfstatat", "-s", "200", BIN],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return p.stdout, p.stderr

def mkdir_p(path: str):
    path = path.rstrip("/")
    if not path:
        return
    os.makedirs(path, exist_ok=True)

def main():
    if not os.path.exists(BIN):
        print(f"[-] Can't find {BIN} in current directory.")
        sys.exit(1)

    for step in range(1, 5000):
        out, err = run_strace()

        # If the program prints the flag, it will appear on stdout.
        if "We found the treasure!" in out or ("{" in out and "}" in out):
            print(out, end="")
            print(f"[+] Finished at step {step}.")
            return

        m = RE_MISSING.search(err)
        if not m:
            print("[!] No ENOENT path found. stdout was:")
            print(out, end="")
            if err.strip():
                print("\\n[!] strace stderr was:")
                print(err, end="")
            print("\\n[!] If your libc uses different syscalls, trace more (stat/statx/access/openat).")
            return

        missing = m.group(1)

        # Avoid creating absolute paths if something weird happens
        if missing.startswith("/"):
            print(f"[-] Refusing to create absolute path: {missing}")
            return

        mkdir_p(missing)
        print(f"[+] Step {step}: created {missing.rstrip('/')}/")

if __name__ == "__main__":
    main()
```

Run it:

```bash
chmod +x solve.py
./solve.py
```

If your system uses `stat()` instead of `newfstatat()`, you can broaden tracing:

```bash
strace -f -e trace=newfstatat,stat,statx,access,openat ./robber
```

…and adjust the regex accordingly.

---

## 5) Why this reveals the flag

Because the code constructs the path from `parts[]` one character at a time, the directory names correspond to the flag characters in order. Creating each missing directory allows the loop to progress to the next character until the full sequence is validated.

Once all required directories exist, the loop completes and the binary prints:

```
We found the treasure! (I hope it's not cursed)
```

…and (in the challenge) reveals the flag.

---

## Appendix: Key takeaway

- `parts[]` contains 32 characters.
- The program checks `stat("<prefix>/<next>/.../")` for each prefix.
- You can solve it either by:
  - extracting `parts[]` statically (disassembly), or
  - using the filesystem oracle behavior (dynamic), creating directories until success.
