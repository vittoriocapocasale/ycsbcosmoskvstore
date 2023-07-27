# ycsbcosmoskvstore

Use this with go-ycsb https://github.com/pingcap/go-ycsb.

Download go-ycsb



```
cd go-ycsb
vim ./cmd/go-ycsb/main.go
```
Add this line in the import section: 
```
_ "github.com/vittoriocapocasale/ycsbcosmoskvstore"
```
Close the editor and compile.

```
make
./bin/go-ycsb load kvstore -P workloads/workda
```
