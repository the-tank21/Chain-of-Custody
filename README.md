# CSE469-P1

Group: 20\n
Members:\n
    \tEthan Hodge\n
    \tEaston Kelso\n
    \tAndrew Sheppard\n
    \tMihn Tran\n

The progam begins every execution by reading a provided binary file that
represents a blockcahin. This binary is turned into an array of tuples 
that represent entries in the blockchain. All operations are done on this
array throughout execution. 
The main function creates this array and then reads the command line 
arguments to determine what is next. Each blockchain function (add, 
checkout, verify, remove, etc.) each exist in their own function. With 
the exception of verify, every function takes the array and rewrites it 
to the binary file.
The general flow of each command goes like this:
    1) Read binary and convert to array of tuples
    2) Read command line argument and execute corresponding function
    3) Add blockchain tuple to array
    4) Convert each tuple into bytes and write to file
Ewrror checking is done at every step of execution. The program exits 
with a 1 the second any error is detected.
