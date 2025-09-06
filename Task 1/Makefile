SHELL := C:/Windows/System32/cmd.exe
.SHELLFLAGS := /c

PYTHON := py -3
PCAP := 3.pcap
SERVER_IP := 127.0.0.1
SERVER_PORT := 53535
REPORT := report.csv
RULES := rules.json
CLIENT_DELAY := 2

.PHONY: all 

all: run

server:
	$(PYTHON) server.py --rules $(RULES)

client:
	$(PYTHON) client.py --pcap $(PCAP) 

run:
	@echo Starting server in a new cmd window...
	@start "Server" cmd /k "$(PYTHON) server.py --rules $(RULES)  & pause"
	@echo Waiting $(CLIENT_DELAY) seconds then starting client in a new cmd window...
	@start "Client" cmd /k "timeout /t $(CLIENT_DELAY) /nobreak > nul & $(PYTHON) client.py --pcap $(PCAP) & pause"
