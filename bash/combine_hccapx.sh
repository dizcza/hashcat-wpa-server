#!/usr/bin/env bash

for file_cap in captures/capture_files/*.cap; do
    cap2hccapx ${file_cap} ${file_cap%.cap}.hccapx
done

cat captures/capture_files/*.hccapx > captures/combined.hccapx
