input=open("sys_call_table.txt","r")
output=open("./headers/sys_call_table.h","w")
output.write("const char * sys_call_table[] = { \n")
for l in input:
        lst=l.split()
        line_to_write="\""+lst[1]+"\",\n"
        output.write(line_to_write)
output.write("};")
output.close()
input.close()

