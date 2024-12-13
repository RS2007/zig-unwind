* Accessing the eh frame section (solved by libdwarf)
* Finding relevant fde:
    * based on frames 
    * CIEs and FDEs in `eh_frame`
    * find the fde correspoinding to the executing function
* Unwinding a single frame:
    * Decoding the fde
    * execcute the fde instructions, find the stack pointer
    *    

