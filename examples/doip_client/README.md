# DoIP Client/Server Example

This example demonstrates the **DoIP (Diagnostic over IP - ISO 13400)** transport layer implementation for UDS (ISO 14229) using TCP.

## Overview

The example consists of:

- **DoIP Server** (`doip_test_server.c`) - Receives UDS diagnostic requests via DoIP and sends responses
- **DoIP Client** (`doip_test_client.c`) - Sends UDS diagnostic requests via DoIP and receives responses
- **Test Script** (`test.sh`) - Automated integration test

## Features

### Client

- Connects to DoIP server via TCP
- Performs routing activation
- Executes UDS diagnostic services (took example from `examples/linux_rdbi_wdbi`):
  - **ReadDataByIdentifier (0x22)** - Reads DID 0xF190
  - **WriteDataByIdentifier (0x2E)** - Writes incremented value to DID 0xF190
- Demonstrates async request/response handling

### Server

- Listens on TCP port 13400 (standard DoIP port)
- UDP discovery is not supported (and not needed)
- Handles routing activation requests
- Processes UDS diagnostic messages:
  - ReadDataByIdentifier (0x22)
  - WriteDataByIdentifier (0x2E)
  - DiagnosticSessionControl (0x10)
- Sends DoIP diagnostic message ACK/NACK
- Responds to alive check requests

## Building

```bash
make
```

This builds two executables:

- `doip_server` - DoIP server
- `doip_client` - DoIP client

## Running

### Manual Test

Start the server in one terminal:

```bash
./doip_server
```

Run the client in another terminal:

```bash
./doip_client
```

The client will:

1. Connect to server at `127.0.0.1:13400`
2. Activate routing
3. Read DID 0xF190
4. Write DID 0xF190 with incremented value
5. Exit

### Automated Test

```bash
./test.sh
```

The test script:

1. Builds both client and server
2. Starts server in background
3. Runs client and waits for completion
4. Verifies client exited successfully (exit code 0)
5. Verifies server is still running
6. Cleans up

## Configuration

Edit `Makefile` to adjust log level:

```makefile
# Debug build with verbose logging
CFLAGS = -DUDS_TP_DOIP=1 -DUDS_LOG_LEVEL=UDS_LOG_VERBOSE

# Release build with info logging
CFLAGS = -DUDS_TP_DOIP=1 -DUDS_LOG_LEVEL=UDS_LOG_INFO
```

## Network Details

- **Protocol**: DoIP over TCP (ISO 13400)
- **Port**: 13400
- **Server IP**: 127.0.0.1 (localhost)
- **Source Address**: 0x0E00 (client logical address)
- **Target Address**: 0x4001 (server logical address)

## DoIP Message Flow

```text
Client                          Server
  |                               |
  |------- TCP Connect ---------->|
  |                               |
  |--- Routing Activation Req --->|
  |<-- Routing Activation Res ----|
  |                               |
  |--- Diagnostic Message ------->|
  |<-- Diagnostic Message ACK ----|
  |<-- Diagnostic Response -------|
  |                               |
  |--- Diagnostic Message ------->|
  |<-- Diagnostic Message ACK ----|
  |<-- Diagnostic Response -------|
  |                               |
  |------- TCP Close ------------>|
```

## Troubleshooting

**Server won't start:**

- Check if port 13400 is already in use: `netstat -tuln | grep 13400`
- Kill any existing server: `pkill doip_server`

**Client can't connect:**

- Verify server is running: `ps aux | grep doip_server`
- Check firewall settings
- Use `tcpdump` to inspect traffic: `sudo tcpdump -i lo port 13400 -X`

**Test script fails:**

- Check exit codes in test output
- Run with verbose logging (edit Makefile)
- Run server and client manually to isolate issues

## References

- ISO 13400: Road vehicles - Diagnostic communication over Internet Protocol (DoIP)
- ISO 14229: Unified Diagnostic Services (UDS)
