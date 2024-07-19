#!/bin/bash
set -e
GHIDRA_INSTALL_DIR="/Applications/ghidraRun.app/Contents/MacOS"
HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
PROJECT_DIR="/Users/oneshell/Documents/Ghidra_Project"
PROJECT_NAME=""

print_help() {
    echo "Usage: $0 -r rootfs [-b binary]"
    echo "Create a Ghidra Project from rootfs"
    echo "  -r rootfs : rootfs directory"
    echo "  -b binary : binary file"
    echo "  -h : print this help"
}

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
            echo "Invalid option: $OPTARG" >&2
            print_help
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            print_help
            exit 1
            ;;
    esac
done

if [ -z "$ROOTFS" ]; then
    echo "rootfs is required" >&2
    print_help
    exit 1
fi

echo "ROOTFS=$ROOTFS"
if [ -n "$BINARY" ]; then
    echo "BINARY=$BINARY"
fi

read -p "Enter project name: " PROJECT_NAME

declare -a import_params
while IFS= read -r dir; do
    import_params+=("-import $dir/*.so* ")
    echo "Importing $dir"
done < <(find "$ROOTFS" -type f -regex '.*\.so[^/]*$' -regex '.*\.so\(\.[0-9]+\)*$' | sed 's|/[^/]*$||' | sort -u)

$HEADLESS "$PROJECT_DIR" "$PROJECT_NAME/libs" \
    $import_params \
    -loader ElfLoader \
    -loader-linkExistingProjectLibraries true \
    -loader-projectLibrarySearchFolder /libs \
    -overwrite \
    -noanalysis

if [ -n "$BINARY" ]; then
    $HEADLESS "$PROJECT_DIR" "$PROJECT_NAME" \
        -import "$BINARY" \
        -loader ElfLoader \
        -loader-linkExistingProjectLibraries true \
        -loader-projectLibrarySearchFolder /libs \
        -overwrite \
        -noanalysis
fi