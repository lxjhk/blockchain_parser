**Blockchain_Parser 1.0**
===================

>**Say thank you by tipping the original author !**  
>**BITCOIN TIP JAR: "1BT66EoaGySkbY9J6MugvQRhMMXDwPxPya"**

This project contains a single C++ code snippet; one header file, one CPP, with no external dependencies, to rapidly and efficiently parse the raw bitcoin block-chain on your hard drive; assuming you are running the official bitcoin client. 

Builds out of the box for either windows with Visual Studio for for Linux using standard make

It also contains individual code snippets to show how to compute an SHA256 and RIPEMD160 hash as well as convert bitcoin addresses to and from binary and ASCII formats.

Finally, it contains a console application which lets you parse and query the blockchain for statistics and reporting.

Here are some of the articles associated with this project:

>- **The main original article**:

>- http://codesuppository.blogspot.com/2013/07/bitcoin-code-snippets.html

>- **An article documenting the blockchain in great detail:**

>- http://codesuppository.blogspot.com/2014/01/how-to-parse-bitcoin-blockchain.html

>- **An article documenting how to use the console app and a binary download:**

>- http://codesuppository.blogspot.com/2014/01/a-command-line-interface-for-blockchain.html




Update January 2, 2015
-------------

- This code was refactored over Christmas break of 2014. Changes made were:

- Now properly detects 'stealth addresses'

- Now properly detects multi-sig addreses

- Now properly reports pay-to-script hash addresses

- Minor changes to accommodate a much larger blockchain. Now requires a massive amount of memory to run and may not survive another year as it is currently implemented. This code loads the entire blockchain into memory, but now the blockchain is so large this is no longer practical. The code will probably need to be substantially refactored to use some sort of disk-based mechanism to parse the whole blockchain, either memory mapped files or a formal database.

- A new report is now generated breaking down the number and volume of new public key addresses generated per day

- The program is now command line driven.

- The original version had a single source file (blockchain.cpp) to implement everything. The code was cleaned up now, and it has several dependent source files which is easier to follow and maintain

Documentation
-------------
#### <i class="icon-file"></i> Code Structure
**Base58** : This is a code snippet which performs base58 encoding and decoding.  This implementation is based on the code from the 'cbitcoin' project; but heavily refactored to remove all memory allocations.  Converting to and from base58 is surprisingly complicated as you have to do 'large integer' arithmetic.  This sample contains just enough code to do the base58 encode/decode process and nothing more.  It does not do the 'check' step, as that is bitcoin specific, and done by a different piece of code.

The header file: Base58.h
The implementation source: Base58.cpp

**SHA256** : To compute the transaction hash and some other important hashes in bitcoin you need code to compute an SHA256 hash.  This code snippet is based pretty much directly on the original version by Zilong Tan.

The header file: SHA256.h
The implementation: SHA256.cpp

**RIPEMD160** : To compute a bitcoin address from a public key (read the documentation) you need to have access to a RIPEMD160 hash.  This source is based pretty much directly on the original reference version written by Anton Bosselaers way back in 1996 but still works just fine today.

The header file: RIPEMD160.h
The implementation: RIPEMD160.cpp

**BitcoinAddress** : This is probably the single most valuable and useful code snippet provided.  This piece of code folds in all the previous snippets (Base58, SHA256, RIPEMD16) and shows how you convert a bitcoin public-key into a bitcoin binary address and how to convert that address to ASCII or from ASCII back to binary using base58 encoding.  It took a lot of digging to put this bit of magic together; and this code is very well documented.  

The header file: BitcoinAddress.h
The implementation : BitcoinAddress.cpp

**BlockChain** : Finally; this is the grandaddy of the code snippets.  This single piece of code folds in all of the snippets above into a snippet which can parse the entire bitcoin blockchain.  It is not yet complete.  It still needs to produce a list of all transactions throughout history, I am still working on that.  However, the state that the code is in can already produce much of the information you see on the block explorer website.

The header file: BlockChain.h
The implementation: BlockChain.cpp

If you browse the repository, you will see there is also some code called 'BitcoinScript' and 'BitcoinTransactions', those are not implemented and may or may not ever be completed.





License
-------------------
![MIT](http://opensource.org/trademarks/opensource/OSI-Approved-License-100x137.png)  **Under The MIT License (MIT)**


**Copyright (c) <2015> <lxjhk>**

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.