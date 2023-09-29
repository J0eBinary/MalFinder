# MalFinder
This tool takes a PE file (e.g. *.exe) and checks if the Import Address Table (IAT) contains a suspicious function that is usually used in malware.
The process is done by checking if the function name is present at https://malapi.io/ . If so, the tool returns the description of the function and what it is used for.

## Installation

```
git clone https://github.com/J0eBinary/MalFinder.git
```
## Dependencies:

MalFinder depends on the `requests`, `pefile` and `sys` python modules.

These dependencies can be installed using the requirements file:
```
sudo pip3 install -r requirements.txt
```

## Usage
```
python3 MalFinder.py malware.exe
python3 MalFinder.py mal_library.dll
```

### Contact 
* X: [J0e_Binary](https://twitter.com/j0e_Binary)

## Version
**Current version is 1.0**
