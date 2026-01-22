# Makefile for Secure Multi-Client Communication System
# SNS Lab Assignment 1

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -g
LDFLAGS = -lssl -lcrypto -lpthread

# Source files
CRYPTO_SRC = crypto_utils.cpp
PROTOCOL_SRC = protocol_fsm.cpp
COMMON_OBJS = crypto_utils.o protocol_fsm.o

# Targets
SERVER = server
CLIENT = client
ATTACKS = attacks

.PHONY: all clean test help

all: $(SERVER) $(CLIENT) $(ATTACKS)

# Object files
crypto_utils.o: crypto_utils.cpp crypto_utils.hpp common.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

protocol_fsm.o: protocol_fsm.cpp protocol_fsm.hpp crypto_utils.hpp common.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Server
$(SERVER): server.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Client
$(CLIENT): client.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Attack demonstration
$(ATTACKS): attacks.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Run local tests (no server needed)
test-local: $(ATTACKS)
	./$(ATTACKS) -l

# Run server with default settings
run-server: $(SERVER)
	./$(SERVER) -k keys.txt -n 3

# Run a single client
run-client: $(CLIENT)
	@echo "Usage: make run-client ID=1"
	@if [ -n "$(ID)" ]; then \
		KEY=$$(grep "^$(ID):" keys.txt | cut -d: -f2); \
		./$(CLIENT) -i $(ID) -k $$KEY -r 3; \
	else \
		echo "Please specify client ID, e.g., make run-client ID=1"; \
	fi

# Run multiple clients in parallel
run-clients: $(CLIENT)
	@echo "Starting 3 clients in parallel..."
	./$(CLIENT) -i 1 -k $$(grep "^1:" keys.txt | cut -d: -f2) -r 3 &
	./$(CLIENT) -i 2 -k $$(grep "^2:" keys.txt | cut -d: -f2) -r 3 &
	./$(CLIENT) -i 3 -k $$(grep "^3:" keys.txt | cut -d: -f2) -r 3 &
	wait

# Run attack demonstration
run-attacks: $(ATTACKS) $(SERVER)
	@echo "Starting server in background..."
	./$(SERVER) -k keys.txt -n 1 &
	@sleep 1
	@echo "Running attack tests..."
	./$(ATTACKS) -k 0123456789abcdef0123456789abcdef
	@pkill -f "./$(SERVER)" || true

# Full demo
demo: all
	@echo "=== SECURE MULTI-CLIENT COMMUNICATION DEMO ==="
	@echo ""
	@echo "Step 1: Starting server..."
	./$(SERVER) -k keys.txt -n 3 &
	@sleep 1
	@echo ""
	@echo "Step 2: Starting 3 clients..."
	./$(CLIENT) -i 1 -k $$(grep "^1:" keys.txt | cut -d: -f2) -r 2 -d 10 &
	./$(CLIENT) -i 2 -k $$(grep "^2:" keys.txt | cut -d: -f2) -r 2 -d 20 &
	./$(CLIENT) -i 3 -k $$(grep "^3:" keys.txt | cut -d: -f2) -r 2 -d 30 &
	@wait
	@echo ""
	@echo "Step 3: Stopping server..."
	@pkill -f "./$(SERVER)" || true
	@echo "Demo complete!"

# Clean
clean:
	rm -f $(SERVER) $(CLIENT) $(ATTACKS) *.o

# Help
help:
	@echo "Secure Multi-Client Communication System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build server, client, and attacks"
	@echo "  server       - Build server only"
	@echo "  client       - Build client only"
	@echo "  attacks      - Build attack demo only"
	@echo "  test-local   - Run local crypto tests (no server)"
	@echo "  run-server   - Start the server"
	@echo "  run-client   - Run a single client (use ID=n)"
	@echo "  run-clients  - Run 3 clients in parallel"
	@echo "  run-attacks  - Run attack demonstration"
	@echo "  demo         - Full demonstration"
	@echo "  clean        - Remove built files"
	@echo ""
	@echo "Example usage:"
	@echo "  make all"
	@echo "  make run-server     # In terminal 1"
	@echo "  make run-clients    # In terminal 2"
	@echo ""
	@echo "  make demo           # Automatic full demo"
