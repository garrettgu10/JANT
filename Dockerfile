FROM blacktop/ghidra
WORKDIR /dit
COPY . .
RUN /ghidra/support/analyzeHeadless /tmp ghidra -import /dit/sec_salsa20_from_wat -scriptPath /dit -postScript NewScript.java