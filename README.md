# IoTGhidra
a simple script helps IoT Security Researchers to create a Ghidra project which automatically imports all Needed So for the Binary to be analyzed.

```sh
usage: ./IoTGhidra.sh -r rootfs [-b binary]
create a Ghidra Project from rootfs
 -r rootfs : rootfs directory
 -b binary : binary file
 -h : print this help
```

for example:
```sh
$ ./IoTGhidra.sh -r ./rootfs  
ROOTFS=./rootfs
Enter project name: tplink_archer-c2
Importing ./rootfs/lib
......
. Ghidra headless log output
......

$ ./IoTGhidra.sh -r ./rootfs -b ./rootfs/usr/bin/httpd 
ROOTFS=./rootfs
BINARY=./rootfs/usr/bin/httpd
Enter project name: tplink_archer-c2
Importing ./rootfs/lib
......
. Ghidra headless log output
......
```
