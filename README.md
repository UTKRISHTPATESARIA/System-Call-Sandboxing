# System-Call-Sandboxing
Extracting a system call policy from a statically linked binary and using ptrace() to implement and detect for any violation in policy to detect for any attacks. 

This Project was part of [E0-256](https://www.csa.iisc.ac.in/~vg/teaching/E0-256/project.html) course offered @ IISc.

## Using the Tool:

### File repo:

<b>/src :</b> Contains logic for implementing syscall-policy in user space using ptrace along with some other files for pre-processing.<br \>
<b>/test :</b> Contains some test programs and binaries.<br \>
<b>Binary_Analysis.py :</b> Contains the core logic to extract a CFG(NFA) of system calls from any given statically linked library.<br \>

1. Create any statically 
