docker build -t ghidra .

(
    docker run --init --rm \
    --cpus 4 \
    --memory 4g \
    -e MAXMEM=4G \
    -v `pwd`:/dit \
    -v $(realpath $1):/to_analyze \
    ghidra \
    support/analyzeHeadless /tmp ghidra -import /to_analyze -scriptPath /dit -postScript NewScript.java
)# | grep "(GhidraScript)" | sed -e 's/\(INFO  NewScript.java> \| (GhidraScript)\)//g'