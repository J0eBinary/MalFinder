# MalFinder
This tool takes a PE file (e.g. *.exe) and checks if the Import Address Table (IAT) contains a suspicious function that is usually used in malware.
The process is done by checking if the function name is present at https://malapi.io/ . If so, the tool returns the description of the function and what it is used for.

## Installation

```
git clone https://github.com/oh-az/MalFinder.git
cd MalFinder
```
## Dependencies

dependencies can be installed using the requirements file:
```
sudo pip3 install -r requirements.txt
```

## Usage
```
python3 MalFinder.py malware.exe
python3 MalFinder.py mal_library.dll
```
![Capture](https://github.com/oh-az/MalFinder/assets/74332587/742bd180-c5d0-41bb-8778-00af44777a9e)
![image](https://github.com/J0eBinary/MalFinder/assets/55762160/a9b48eec-e663-433f-8629-57b9a31ba595)


## Added Features
these new features are add by [oh-az](https://github.com/oh-az)
*	Detect the use of Direct Syscalls by disassembling the binary and looking into it.
  
![Capture2](https://github.com/oh-az/MalFinder/assets/74332587/b4fc4c4b-e56d-48ff-a8c8-05702f0f7436)

*	Display information about the binary.
*	Calculate each section's entropy to detect potential obfuscation/packing
  
![Capture](https://github.com/oh-az/MalFinder/assets/74332587/742bd180-c5d0-41bb-8778-00af44777a9e)

*	Calculate each section's virtual and raw size to detect the potential of packing.
  
![Capture3](https://github.com/oh-az/MalFinder/assets/74332587/e188ed1b-d404-43c2-9c92-fec73090d9a1)

*	Extract all IPs from the binary.

    ![Capture4](https://github.com/oh-az/MalFinder/assets/74332587/ba513795-9b86-46d3-a5e5-eee10b0d951c)

*	Calculate the MD5 hash and sends it to VirusTotal, then it prints out how many vendors have flagged this binary.
  
![Capture5](https://github.com/oh-az/MalFinder/assets/74332587/26e03b69-9872-4d2e-9939-1402a6213a43)




### Contact 
* X: [J0e_Binary](https://twitter.com/j0e_Binary)
* X: [ohAz](https://twitter.com/AzizWho)

## Version
**Current version is 1.2**
