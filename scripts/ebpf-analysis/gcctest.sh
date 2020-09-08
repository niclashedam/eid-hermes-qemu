#!/bin/bash
set +e
gcc patmatch.c -o patmatch.o -D DEBUG
echo "Build Complete"
chmod a+x patmatch.o
./patmatch.o
# printf "Return Value: $hexout (%d)\n" $((16#${hexout:2}))
# printf "Return Value: $hexout"
