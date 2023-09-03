# System-Call-Sandboxing
Extracting a system call policy from a statically linked binary and using ptrace() to implement and detect for any violation/deviation in policy that can result in attacks. 

This Project was part of [E0-256](https://www.csa.iisc.ac.in/~vg/teaching/E0-256/project.html) course offered @ IISc.

## Using the Tool:

### File repo:

<b>/src :</b> Contains logic for implementing syscall-policy in user space using ptrace along with some other files for pre-processing.<br>
<b>/test :</b> Contains some test programs and binaries.<br>
<b>Binary_Analysis.py :</b> Contains the core logic to extract a CFG(NFA) of system calls from any given statically linked library.<br>

++ Unzip the file under any directory
++ To run the program use the following command

```
$ cd final
$ python BinaryAnalysis.py </path/to/binary>
```

(Ignore the errors/warning thrown on screen, its part of CFGFast)

++ After running syscall-policy.DOT and nodes-syscall.txt file will be created under src/ directory

++ The src directory also contains other pre-processed files along with a headers directory which contains mappings from syscall numbers to names.

++ tracing.cpp is the system-call-policy-monitor implemented using ptrace which takes the graphi and static compiled binary  as input and detects any violation in syscall policy

++ /test directory has few pre-compiled static libraries.

++ Running the monitor:

```
$ ./src/tracing ./test/loop
```
This will generate an output, and print and ABORT program if violation detected.
