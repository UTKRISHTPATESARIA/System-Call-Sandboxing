import angr
from angrutils import *
import monkeyhex
import networkx
import sys

proj = angr.Project(sys.argv[1])
cfg = proj.analyses.CFGFast(show_progressbar = True)

file1 = open(r"./src/nodes-syscall.txt", "w")
    
G = networkx.DiGraph()
vis = {}
paths = []
last_call = ''
prev_stack = []
num = 0
node_name = ''
loop_flag = 0
loop_blocks = []
gibberish = []
sys = 0

'''
    proj:              Object of angr.Project
    cfg:               Object of angr.CFGFast
    G:                 NetworkX Di-graph of syscalls
    vis:               Dicitonary of visited array stored as follows
                        1. vis[funtion_name] - Key contains a list of values
                        2. list[0] - whether node is unvisited(0),  uexplored(1), explored(2)
                        {DFS implementation}
                        3. list[1] - whether the descendant of the node contains a syscall(0/1)

    paths:              List that stores all unique path to a syscall.
    last_call:          String that stores last syscall visited
    prev_stack:         Storing last syscall path
    num:                To add unique edge for syscalls
    sys:                To assign which library does syscall belong to.
    node_name:          Stores the last syscall node name
    loop_flag:          Whether we are currently exploring nodes part of a loop
'''

syscall_order = []

def generate_gibberish():
    file = open("./src/gibberish.txt")
    for line in file:
        gibberish.append(line.split("\n")[0])
        
def generate_graph(list1, val):
    '''
        Function to generate final syscall graph
        Takes as 2 param a list and a string value of last syscall
        Edges and nodes are added from the list.
        
        flag:       check whether previous syscall has been linked to the current new path
        pos:        position indexing in list1
        edge_list:  two tuple list to store edges
        
    '''
    pos = 0
    edge_list = []
   
    while pos < len(list1) - 2:
        v = list1[pos]
        v1 = list1[pos + 1]
        edge_list = [(v, v1)]
        G.add_edges_from(edge_list, label='epsilon')
        G.add_node(v, label="")
        pos += 1
    
    global num, sys
    node_name = '_' + str(sys) + '_' + str(num)
    if loop_flag:
        file1.write(str(sys) + " " + list1[pos + 1] + " " + "lo" + "\n")
    else:
        file1.write(str(sys) + " " + list1[pos + 1] + "\n")
    edge_list = [(list1[pos], node_name)]
    G.add_edges_from(edge_list, label=list1[pos + 1])
    G.add_node(list1[pos], label="")
    G.add_node(node_name, label='', color='blue', style='filled')
    num += 1    
    return '_' + str(sys) + '_' + str(num - 1)

def add_return_edge(stack, prev_stack, last_sys_call, node_name):
    pos = 0
    prev_node = ''
    while pos < len(stack) and pos < len(prev_stack):
        node1 = prev_stack[pos]
        node2 = stack[pos]
        if(node1 == node2):
            prev_node = node2
            pos += 1
            continue
        else:
            edge_list = [(node_name, prev_node)]
            G.add_edges_from(edge_list, label='epsilon')
            return
    edge_list = [(node_name, prev_node)]
    G.add_edges_from(edge_list, label='epsilon')
    
def mark_syscall(node_list):
    '''
        Function that marks vis[node_list][1] as true, all the predecessors of syscall node
        have seen a syscall in their path
    '''
    for i in node_list:
        node1 = cfg.kb.functions[i]
        vis[node1][1] = 1
        
def check_duplicate(stack, prev_stack):
    i = len(stack)
    j = len(prev_stack)
    if i != j:
        return 0
    
    while i and j:
        if stack[i - 1] != prev_stack[j - 1]:
            return 0
        i = i - 1
        j = j - 1
    return 1

def check_recursion(source, out_nodes):
    blocks = source.block_addrs
    
    for i in out_nodes:
        if source.get_call_target(i) in blocks:
            return i
    return 0

def mark_non_visited(stack):
    for key in vis:
        if key not in stack:
            vis[key][0] = 0
            vis[key][1] = 0
            
def check_loops(source):
    bb = source.transition_graph
    ex = 1
    try:
        loops = nx.find_cycle(bb, orientation="original")
    except:
        ex = 0
        pass
    
    global loop_blocks
    if ex:
        for loop in loops:
            if(loop[0].addr > loop[1].addr):
                succ = loop[1].successors()
                for s in succ:
                    if isinstance(s, angr.knowledge_plugins.functions.function.Function):
                        loop_blocks.append(loop[1].addr)
    return ex

def find_paths(source, stack, curr_loop):
    '''
        ++ Core logic where we find unique reachable path to syscalls.
        ++ Accordingly when we reach a syscall which is a leaf node in the graph, the stored path
           is sent to the generate_graph()
        ++ It is a modified DFS where we visit the nodes depth first.
        ++ We mark nodes as unvisited, exploring, explored.
        ++ Also we keep track of which nodes have syscalls
        
        out_nodes:    list storing all function calls from one node.
        target_addr:  address of called function
        val:          'Function' object of target_addr
        stack:        list storing paths to syscall
        edge_list:    two tuple list storing edges which are added to final Graph
    '''
    
    out_nodes = source.get_call_sites()
    vis[source] = []
    vis[source].append(1)
    vis[source].append(0)
    is_rec = 0
    ex = 0
    
    if source.name not in gibberish:
        global loop_flag, loop_blocks

        if check_recursion(source, out_nodes):
            loop_flag = 1
            is_rec = 1
        else:
            ex = check_loops(source)
    
    for i in out_nodes:
        target_addr = source.get_call_target(i)
        val = cfg.kb.functions[target_addr]
        
        if ex and i in loop_blocks:
            loop_flag = 1
            curr_loop = i
        
        if val.is_syscall:   
            mark_syscall(stack)
            stack.append(val.name)

            global last_call, prev_stack, node_name
            prev_stack.append(last_call)
            name = ''
            if not check_duplicate(stack, prev_stack):
                prev_stack.pop()
                name = generate_graph(stack, prev_stack)
            else:
                prev_stack.pop()
                stack.pop()
                continue
                
            k = stack.pop()
            if len(prev_stack):
                add_return_edge(stack, prev_stack, last_call, node_name)
            last_call = k
            prev_stack = stack.copy()
            node_name = name
            
            #Adding self loops to syscall if it is a part of a loop/recursion
            if loop_flag:
                edge_list = [(node_name, node_name)]
                G.add_edges_from(edge_list, label = k)
            continue
        
        if vis.get(val):
            if vis.get(val)[0] == 1:
                    continue
                
            elif vis.get(val)[0] == 2:
                if val.name in gibberish and source.name not in gibberish:
                    vis.get(val)[0] = 0
                    vis.get(val)[1] = 0
                    mark_non_visited(stack)
                else:
                    continue
                
                if vis.get(val)[1] == 1:
                    if val.name in gibberish:
                        continue

        stack.append(val.name)
        #Check if a new library call is invoked and change the variables accordingly
        if val.name in gibberish and source.name not in gibberish:
            global sys
            sys = sys + 1
            mark_non_visited(stack)
        find_paths(val, stack, curr_loop)

        #The node val has been explored hence pop it out
        if len(stack):
            top = stack.pop()
            
        if curr_loop == i:
            loop_blocks.remove(i)
            loop_flag = 0
            curr_loop = ''

    vis[source][0] = 2
    if is_rec:
        is_rec = 0
        loop_flag = 0
    
def main():
    stack = []
    func = cfg.kb.functions['main']
    stack.append(func.name)
    out_nodes = func.get_call_sites()
    
    vis[func] = []
    vis[func].append(1)
    vis[func].append(0)
    G.add_node(func.name, label = "S", color='red', style='filled')
    curr_loop = ''
    #for i in out_nodes:
    generate_gibberish()
    find_paths(func, stack, curr_loop)
    
    #Adding exit node
    edge_list = [(node_name, "exit")]
    G.add_edges_from(edge_list, label = '')
    G.add_node("exit", label = '', color = 'black', style = 'filled')
    
    #Removing epsilon edges from main and keeping only for 1st.
    out_list = list(G.out_edges("main"))
    for i in out_list[1:]:
        G.remove_edge(i[0], i[1])
        
    #Removing unreachable nodes
    for i in list(G.nodes):
        if i.startswith("main"):
            continue
        if not G.in_degree(i):
            G.remove_node(i)
           
    nx.drawing.nx_pydot.write_dot(G, './src/syscall-policy.dot')
    file1.write(str(sys + 1) + " " + "exit_group")
    file1.close()

#Driver Code
main()
