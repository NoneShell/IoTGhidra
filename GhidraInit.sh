#!/bin/bash
GHIDRA_INSTALL_DIR=/Applications/ghidraRun.app/Contents/MacOS
HEADLESS=$GHIDRA_INSTALL_DIR/support/analyzeHeadless
PROJECT_DIR=/Users/oneshell/Documents/Ghidra_Project

print_help() {
    echo "usage: $0 -r rootfs [-b binary]"
    echo "create a Ghidra Project from rootfs"
    echo " -r rootfs : rootfs directory"
    echo " -b binary : binary file"
    echo " -h : print this help"
}

# check args
ROOTFS=""
BINARY=""
while getopts "r:b:h" opt; do
    case $opt in
        r)
            ROOTFS=$OPTARG
            ;;
        b)
            BINARY=$OPTARG
            ;;
        h)
            print_help
            exit 0
            ;;
        \?)
            echo "Invalid option: $OPTARG" 1>&2
            print_help
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." 1>&2
            print_help
            exit 1
            ;;
    esac
done

if [ -z "$ROOTFS" ]; then
    echo "rootfs is required" 1>&2
    print_help
    exit 1
fi

echo "ROOTFS=$ROOTFS"
if [ -n "$BINARY" ]; then
    echo "BINARY=$BINARY"
fi

# 1. create project from rootfs and import all libraries
read -p "Enter project name: " PROJECT_NAME
declare -a import_params
while read -r dir; do
    import_params+=("-import $dir/*.so* ")
    echo "Importing $dir"
done < <(find "$ROOTFS" -type f -name "*.so*" | sed 's|/[^/]*$||' | sort -u)

$HEADLESS $PROJECT_DIR $PROJECT_NAME/libs \
    $import_params \
    -loader ElfLoader \
    -loader-linkExistingProjectLibraries true \
    -loader-projectLibrarySearchFolder /libs \
    -overwrite \
    -noanalysis

# 2. import binary if exists
