FROM blacktop/ghidra:latest
# we need to replace the analyzeHeadless script to make the stack 1g
COPY analyzeHeadless /ghidra/support 
RUN chmod +x /ghidra/support/analyzeHeadless