#define _POSIX_C_SOURCE 200112L
#include <bits/stdc++.h>
#include <fstream>
#include <string>
/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
using namespace std;

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include "./headers/sys_call_table.h"
#include <sys/ptrace.h>
#include <ctype.h>
#include <libaudit.h>

std::vector<string> initial_list{"arch_prctl", "brk", "brk", "arch_prctl", "uname", "readlink", "brk", "brk", "mprotect"};

int pos = 0;
int npos = 1;
int initial = 0;
int loop = 0;
std::map<int, vector<string>> nodes;

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


std::string find_call_name(std::string line){
    int flag = 0;
    string name;

    for(auto x : line){
        if(x == ' ' && flag)
            return name;
        
        if(x == ' '){
            flag = 1;
            continue;
        }
        
        if(flag)
            name += x;
    }
    return name;
}

void create_graph(){
    ifstream fin;
    fin.open("./src/nodes-syscall.txt");
    std::string line;
    getline(fin, line);
    int count = 1;

    while(fin){
        string key = to_string(count);

        if(line.find(key) != string::npos){
            if(line.find(" lo") != string::npos){
                nodes[count].push_back("loop");
            }
            nodes[count].push_back(find_call_name(line));
            getline(fin, line);
        }
        else 
        count++;
    }
}

int check_initial_frontier(std::string syscall){

    if(syscall == initial_list[pos]){
        cout << "Detected by Monitor :" <<  initial_list[pos] << endl;
        pos++;
        if(pos == initial_list.size())
            return 1;
        else    
            return 0;
    }

    return 1;
}
int check_frontier(std::string syscall){

    vector<string> it1 = nodes[npos];
    if(find(it1.begin(), it1.end(), "loop") != it1.end())
        loop = 1;

    if(find(it1.begin(), it1.end(), syscall) != it1.end()){
        if(!loop) npos++;
        cout << "Detected by monitor : " << syscall << endl;
	if (syscall == "exit_group")
		cout<<"\n+++++++++++++SUCCESSFUL DETECTION NO VIOLATIONS+++++++++\n";
        return 1;
    }

    return 0;
}


int main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);
    create_graph();
    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* Because we're now a tracee, execvp will block until the parent
             * attaches and allows us to continue. */
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with execvp
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));
        long syscall = regs.orig_rax;
       
       //fprintf(stderr, "Syscall : %s\n", sys_call_table[syscall]);

       cout << "Invoked Syscall : " << sys_call_table[syscall] <<endl;
        
       if(!initial){
            initial = check_initial_frontier(sys_call_table[syscall]);
        }
       else{
            while(!check_frontier(sys_call_table[syscall])){
                cout << "\n!!!!!FRONTIER VIOLATION DETECTED!!!\nThe invoked syscall can be part of if-else, switch statements, forwarding to next frontier\n";
                if(loop){
                    npos++;
                    loop = 0;
                    continue;
                }
                else if(npos < nodes.size() - 1) {
                    npos++;    
                    continue;
                }
        
                cout << "!!!!!!!!!ABORTING PROGRAM!!!!!!!!!" << endl;
                exit(0);
            }
        }

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

         //Get system call result 
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            //fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

    }
    return 0;
}
