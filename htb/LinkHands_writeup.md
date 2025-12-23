# LinkHands – Reversing Writeup

## Challenge Info
- **Name:** LinkHands  
- **Difficulty:** Easy  
- **Category:** Reversing  
- **Concepts:** Global variables, linked lists, arbitrary write  

---

## Overview

The binary asks the user:

> *"The cultists look expectantly to you - who will you link hands with?"*

Supplying random input fails. The correct solution requires understanding how the program stores and prints a flag using **two linked lists stored in global memory**, and how user input can be used to link them together.

---

## Program Behavior

After decompilation, the main logic can be summarized as:

1. Read a line of input
2. Parse **two pointers** using `sscanf("%p %p")`
3. If parsing succeeds:
   - Write the second pointer to the memory location specified by the first
   - Traverse a global linked list and print one character per node

The critical line is:

```c
*ptr1 = ptr2;
```

This gives the user an **arbitrary write** primitive.

---

## Linked List Structure

From analysis of the `.data` section, each node has the layout:

```c
struct ListNode {
    struct ListNode *next; // 8 bytes
    char c;                // character
};
```

The printing loop does:

```c
for (node = &head; node != NULL; node = node->next)
    putchar(node->c);
```

---

## Identifying the Global Lists

### First List (Partial Flag)

Following the global head pointer (`PTR_PTR_00404190`) reveals a chain spelling:

```
HTB{4_...
```

This list **ends early** at a node containing `'_'`:

- Address: `0x404060`
- `next = NULL`
- `c = '_'`

---

### Second List (Remaining Flag)

Immediately after the first list in memory, another list exists:

- Starts at address: `0x404070`
- First character: `'c'`
- Continues with valid `next` pointers
- Ends with `'}'`

This list is **not linked** to the first.

---

## Exploitation Strategy

To print the full flag, we must link the two lists:

```c
A_last->next = B_first;
```

Because `next` is the first field in the struct, the address of the node is also the address of `next`.

### Required Write

- **ptr1 (where):** `0x404060` (last node of first list)
- **ptr2 (what):** `0x404070` (first node of second list)

---

## Final Input

Run the binary and enter:

```
0x404060 0x404070
```

This causes the program to link the lists and print the full flag.

---

## Key Takeaways

- Always inspect `.data` when a program iterates over globals
- Pointer + character patterns often indicate linked structures
- `%p` input combined with `*ptr = value` is a strong exploitation primitive
- Applying structs in a decompiler greatly simplifies analysis

---

## Flag

The program prints the full flag after linking the lists successfully.
