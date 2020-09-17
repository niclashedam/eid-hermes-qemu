#/bin/bash

IN_F=$1
OUT_F=$2
SECTION=$3

objdump -h $IN_F |
  grep $SECTION |
  awk '{print "dd if='$IN_F' of='$OUT_F' bs=1 count=$[0x" $3 "] skip=$[0x" $6 "]"}' |
  bash