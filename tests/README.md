libhello\_libs.so:
* double-free and use-after-free both in same basic block 
* use-after-free is sandwiched between the double-free
* use-after-free as function argument

libhello\_libs1.so:
* same as before but use-after-free with direct dereference

libhello\_libs2.so:
* double-free but first free inside an if-stmt that is inside a loop
```
for (int i=0; i<len; i++) {
    if (len > 10) {
        free(msg);
    }
}
free(msg);
```
* FP since first free is also signaled to have double free

need\_alias.out:
* requires alias analysis to detect the double-free
