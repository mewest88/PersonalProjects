# Fuse Encrypted Filesystem

## Included Files
The included files are fuse.py, encfs.py, and encfsStarterCode.py.

The code that I made changes to and that needs to be run is in encfs.py.

Compile the program with python3

I created two files in my drive and I called one PhysicalSpace, which I where I stored the physicalm, encrypted files. I also created a folder called VirtualSpace, and this is where I mounted Fuse and this would run all the commands in encfs.py.

When running the compile line below, swap out PhysicalSpace/ and VirtualSpace/ with the names of the folders you create.

To run the file, in the command line run
```
python3 encfs.py PhysicalSpace/ VirtualSpace/
```
To test I did a combination of cat and echo. For example I did.
```
echo "Testing Create" > VirtualSpace/testFile1
```
or
```
cat VirtualSpace/testFile1
```
