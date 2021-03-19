(
    docker run --init -it --rm \
    --name ghidra \
    --cpus 4 \
    --memory 4g \
    -e MAXMEM=4G \
    -v `pwd`:/dit \
    -v $(realpath $1):/to_analyze \
    blacktop/ghidra \
    support/analyzeHeadless /tmp ghidra -import /to_analyze -scriptPath /dit -postScript NewScript.java
)# | grep "(GhidraScript)" | sed -e 's/\(INFO  NewScript.java> \| (GhidraScript)\)//g'