### REQUIREMENTS
Run this command after `git clone` to fetch RandomX library
```
git submodule update --init --recursive
```
### BUILD

On Linux, make sure `cmake` and `make` commands are installed and then run:
```
mkdir build;
cd build;
cmake ../;
make;
```

On Windows, use the CMake GUI to create a Visual Studio project and then build the executable in Visual Studio.


### USAGE
`./oc_verifier [nodeip0] [nodeip1] ... [nodeipN]`
