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

The verifier currently supports **three modes running in parallel**:

1. **Fetch and verify from peers**
   - Fetch tasks and nonces from a list of peers.
   - Perform verification locally.
   - If `--seed` and `--nodeip` are provided, the result will be submitted to the specified node.

2. **Fetch and verify from a specific node (with OPERATOR seed)**
   - Fetch tasks and nonces directly from a node using the OPERATOR seed.
   - Perform verification locally.

3. **Submit verification results to a node (with OPERATOR seed)**
   - Submit verification results to the specified node.
   - This mode is **enabled automatically** when both `--seed` and `--nodeip` are provided.

---

## Notes

- Mode (1) submits results **only if** `--nodeip` and `--seed` are provided.
- Mode (3) is **automatically enabled** when both `--nodeip` and `--seed` are set.

---

## Commands

```bash
# Fetch tasks and solutions from a list of peers and verify without submitting results
./oc_verifier --peers [nodeip0],[nodeip1],...,[nodeipN]

# Fetch tasks and solutions from a specific node and submit verification results
./oc_verifier --seed [OPERATOR seed] --nodeip [OPERATOR IP]

# Fetch from both peers and node, and submit results
./oc_verifier --peers [nodeip0],[nodeip1],...,[nodeipN] --seed [OPERATOR seed] --nodeip [OPERATOR IP]
```
Screenshot:
![image](https://github.com/user-attachments/assets/c629abc8-afb9-4d05-97c5-487456946774)
