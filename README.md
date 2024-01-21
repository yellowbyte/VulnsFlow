Testing
-------
pytest 

Type Checking
-------------
mypy detector.py


Implemented
-----------
* flow-sensitive alias analysis 
  * [alias analysis with data flow](https://www.cs.cornell.edu/courses/cs6120/2020fa/lesson/9/)
* use-after-free
* double free

To Implement
------------
* null-pointer dereference 
  * Precise Interprocedural Dataflow Analysis via Graph Reachability
  * A Single-Machine Disk-Based Graph Sys- tem for Interprocedural Static Analyses of Large-Scale Systems Code
  * Chianina: An Evolving Graph System for Flow- and Context-Sensitive Analyses of Million Lines of C Code
* belief analysis-based null pointer dereference 
  * How to Build Static Checking Systems Using Orders of Magnitude Less Code
  * Checking System Rules Using System-Specific, Programmer-Written Compiler Extensions
  * Chianina: An Evolving Graph System for Flow- and Context-Sensitive Analyses of Million Lines of C Code
* OS command injection
  * Scaling JavaScript Abstract Interpretation to Detect and Exploit Node.js Taint-style Vulnerability
* arbitrary code execution
  * Scaling JavaScript Abstract Interpretation to Detect and Exploit Node.js Taint-style Vulnerability
* path traversal
  * Scaling JavaScript Abstract Interpretation to Detect and Exploit Node.js Taint-style Vulnerability

TODOs
-----
* reachability analysis for automatic exploits generation

