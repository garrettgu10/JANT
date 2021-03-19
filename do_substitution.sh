#!/bin/bash

SUBST_FILE=$1.subst
O_FILE=$1.o
OUT_FILE=$1.out

FIRST_LINE=`sed -n "1p" < $SUBST_FILE`
SECOND_LINE=`sed -n "2p" < $SUBST_FILE`

if [[ $(echo -n "$FIRST_LINE" | wc -c) != $(echo -n "$SECOND_LINE" | wc -c) ]]
then
    echo "substitution file's line lengths mismatch"
    exit
fi

bbe -e "s/$FIRST_LINE/$SECOND_LINE/g" $O_FILE > $OUT_FILE

if [[ ! $(diff $O_FILE $OUT_FILE) ]] 
then
    echo "warning: .out file is identical to .o file"
fi