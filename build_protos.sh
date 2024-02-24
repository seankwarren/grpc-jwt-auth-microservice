#!/bin/bash

# Directory containing proto files and generated python
PROTO_DIR="src/protos"

# Create the output directory if it doesn't exist
mkdir -p ${PROTO_DIR}
touch ${PROTO_DIR}/__init__.py

# Find all proto files in the proto directory
PROTO_FILES=$(find ${PROTO_DIR} -name "*.proto")

echo "Compiling protos in ${PROTO_DIR}"

compilation_success=true
# Run the protocol buffer compiler for each proto file
for PROTO_FILE in ${PROTO_FILES}; do
    echo "Compiling ${PROTO_FILE}"
    python3 -m grpc_tools.protoc \
        -I${PROTO_DIR} \
        --python_out=${PROTO_DIR} \
        --grpc_python_out=${PROTO_DIR} \
        --mypy_out=${PROTO_DIR} \
        ${PROTO_FILE}
        if [ $? -ne 0 ]; then
            compilation_success=false
            echo "Compilation failed for ${PROTO_FILE}"
            break # Optional: remove this line if you want to attempt compiling all files even if some fail
        fi
done

if $compilation_success; then
    echo "All proto files successfully compiled."
else
    echo "Compilation failed."
fi
