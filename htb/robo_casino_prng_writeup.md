# Robo Casino – PRNG Seed Reversal Writeup

## Challenge Summary

The binary presents a casino-style game where the user must repeatedly input characters. For each correct input, the program advances to the next round. A total of **30 correct inputs** are required to finish the challenge.

Despite appearing to rely on randomness, the program is fully deterministic and can be reversed by analyzing how it uses `srand()` and `rand()`.

---

## Relevant Decompiled Code

```c
ret = scanf("%c", &user_input);
if (ret != 1)
    break;

srand((int)user_input);
if (rand() != check[i])
    exit(-2);
```

---

## How the Logic Works

### 1. Input Handling with `scanf`

- `scanf("%c", &user_input)` reads **exactly one byte** from input.
- It stores that byte in `user_input`.
- The return value of `scanf` is the number of **successfully matched format items**.

For `%c`, this means:
- Return value is `1` if one character was read successfully.
- Return value is `EOF` or `0` on failure.

The program checks:

```c
if (ret != 1)
    break;
```

This simply ensures that input was read correctly.

---

### 2. Seeding the PRNG

```c
srand((int)user_input);
```

- The user-controlled character is cast to an integer.
- This integer becomes the **seed** for the pseudo-random number generator (PRNG).

Important detail:
- The seed is **only one byte**, meaning there are at most **256 possible seeds**.

---

### 3. Single Call to `rand()`

```c
value = rand();
```

- Only the **first output** of `rand()` is used.
- The PRNG state is discarded immediately afterward.
- There is **no random sequence**, only a single deterministic value per seed.

So effectively:

```text
value = first_rand(seed)
```

---

### 4. Comparison Against a Static Array

```c
if (rand() != check[i])
    exit(-2);
```

- `check` is a global array of **30 integers** stored in the binary.
- Each round compares the result of `rand()` with `check[i]`.
- If the values differ, the program exits immediately.

---

## What the Program Is Actually Asking

For each index `i`:

> "Which seed (0–255) makes the **first call** to `rand()` return `check[i]`?"

Each round is **independent**:

```text
check[0] = first_rand(seed_0)
check[1] = first_rand(seed_1)
check[2] = first_rand(seed_2)
...
check[29] = first_rand(seed_29)
```

---

## Extracting `check[]` in Ghidra

1. Locate `check` in the decompiler.
2. Jump to its address in the Listing view.
3. Clear incorrectly defined data.
4. Define it as an array:
   - Type: `int`
   - Length: `30`
5. Copy the values (hex or decimal).

This yields the exact values expected by the program.

---

## Solving the Challenge

Since the seed space is only 256 values, we brute-force:

For each `check[i]`:
1. Try all seeds from `0` to `255`.
2. Call `srand(seed)`.
3. Call `rand()` once.
4. If the result matches `check[i]`, the seed is correct.

Repeat this for all 30 entries.

---

## Why This Is Insecure

- `rand()` is **not cryptographically secure**.
- Re-seeding every round destroys randomness.
- Using a **1-byte seed** makes brute-force trivial.
- All expected values are stored in plaintext in the binary.

---

## Final Takeaway

Although the challenge appears to use randomness, it is actually a deterministic lookup problem. By reversing how the PRNG is seeded and used, all required inputs can be recovered offline with minimal effort.

This pattern is common in CTF challenges and should be recognized immediately when `srand(user_input)` and a single `rand()` call are used together.

