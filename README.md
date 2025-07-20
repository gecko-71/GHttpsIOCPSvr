# GHttpsServerIOCP - A High-Performance HTTPS Server in Delphi

This project is an implementation of an asynchronous, multi-threaded HTTPS server for Windows, written in Delphi. The server utilizes I/O Completion Ports (IOCP) and the native Windows TLS/SSL stack (SChannel), ensuring high performance, scalability, and security.

It serves as an excellent starting point for building your own efficient REST APIs, web services, or other applications that require handling a large number of concurrent HTTPS connections.

## Key Features

- **High Performance and Scalability**: Built on I/O Completion Ports (IOCP), allowing for the efficient handling of thousands of concurrent connections using a small pool of worker threads.

- **Native Windows SSL/TLS**: Uses SChannel, eliminating the need for external libraries like OpenSSL. Supports modern protocols (TLS 1.2, TLS 1.3) and ciphers.

- **Security**:
  - Integrated JWT (JSON Web Token) manager for endpoint authorization (Bearer Token)
  - Advanced request parsing with built-in validation mechanisms to protect against attacks (e.g., CRLF Injection, Request Smuggling)

- **Modern API**:
  - Support for large file uploads (multipart/form-data)
  - Streaming of large file downloads
  - Simple routing system for registering endpoints for GET, POST, etc.

- **Resource Management**:
  - Built-in monitor thread that protects the server from overload (CPU, memory, requests per second)
  - Pool of OverlappedEx objects to minimize memory allocation during runtime
  - Utilizes the FastMM5 memory manager

- **Logging**: Integrated logging system based on the Quick.Logger library, with output to the console and files (with rotation)

- **Clean, Object-Oriented Code**: Written in modern Delphi using classes, interfaces, and generics

## Requirements

- **Delphi**: Version 10.4 Sydney or newer (due to the use of modern language features)
- **Operating System**: Windows (due to the use of WinAPI, IOCP, and SChannel)
- **Dependencies**:
  - QuickLogger
  - FastMM5

> **Note**: Ensure that the paths to the above libraries are added to the Library Path in your Delphi project options.

## Installation and Setup

### 1. Clone the Repository

```bash
git clone [YOUR_REPOSITORY_URL]
cd [DIRECTORY_NAME]
```

### 2. Generate an SSL Certificate

The server requires an SSL certificate to operate in HTTPS mode. For development purposes, you can generate a self-signed certificate for localhost.

Open a Command Prompt (CMD) as an Administrator and execute the following command:

```bash
MakeCert.exe -r -pe -n "CN=localhost" -ss GHttpsIOCPSvr -a sha256 -sky exchange -sp "Microsoft Enhanced RSA and AES Cryptographic Provider" -sy 24
```

> **Important**: 
> - The `MakeCert.exe` tool is part of the Windows SDK. Make sure it is available in your system's PATH.
> - The certificate store name (`-ss GHttpsIOCPSvr`) must match the name specified in the server's code. In this project, it is "GHttpsIOCPSvr".

### 3. Build the Project

Open the `GHttpsIOCPSvr.dpr` file in Delphi and build the project.

### 4. Run the Server

Execute the generated `.exe` file. The server will start on port 8443 and listen for HTTPS connections. The console will display logs indicating the server's startup and status.

## Example Endpoints (API)

Below are examples of how to use the project's defined endpoints with the curl tool.

> **Note**: Since we are using a self-signed certificate, you must add the `-k` (or `--insecure`) flag to your curl commands to bypass certificate verification.

### 1. Root Endpoint

**Method**: GET  
**Path**: `/`  
**Description**: Returns a simple HTML page confirming that the server is running.

```bash
curl -k https://localhost:8443/
```

### 2. Login and Get JWT Token

**Method**: POST  
**Path**: `/login`  
**Description**: Authenticates a user and returns a JWT token in the response.

```bash
curl -k -X POST https://localhost:8443/login \
-H "Content-Type: application/json" \
-d "{\"username\":\"admin\",\"password\":\"password123\"}"
```

**Response**:
```json
{
  "token_type": "Bearer",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 7200
}
```

### 3. Echo JSON (Protected Endpoint)

**Method**: POST  
**Path**: `/echojson`  
**Description**: Echoes back the received JSON object. Requires authorization via a JWT token.

First, obtain an `access_token` from the `/login` endpoint, then use it in the Authorization header.

```bash
# Replace YOUR_JWT_TOKEN with the value from the previous step
TOKEN="YOUR_JWT_TOKEN"
curl -k -X POST https://localhost:8443/echojson \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d "{\"message\":\"Hello, world!\", \"value\": 123}"
```

### 4. Downloading a Large File

**Method**: GET  
**Path**: `/large`  
**Description**: Allows downloading a large binary file (10 MB).

```bash
curl -k -o downloaded_file.bin https://localhost:8443/large
```

### 5. Uploading Files (multipart/form-data)

**Method**: POST  
**Path**: `/upload`  
**Description**: Allows uploading one or more files along with additional form fields.

```bash
# Create a sample file to upload
echo "This is a test file." > file1.txt
curl -k -X POST https://localhost:8443/upload \
-F "file1=@file1.txt" \
-F "file2=@C:\path\to\your\image.jpg" \
-F "user_id=12345"
```

**Response**:
```json
{
	"status": "success",
	"message": "Successfully saved 2 file(s).",
	"files_processed": [...],
	"form_fields": [...]
}
```

## Project Structure

- **GHttpsIOCPSvr.dpr**: The main project file and application entry point. It defines and registers all endpoints.
- **src/GHttpsServerIOCP.pas**: The core of the server. Contains the `TGHttpsServerIOCP` class, which manages the listening socket, IOCP port, worker threads, certificate, and SSL logic.
- **src/GRequest.pas**: An advanced `TRequest` class for parsing and validating incoming HTTP requests.
- **src/GRequestBody.pas**: Helper classes for parsing the request body, including multipart/form-data.
- **src/GResponse.pas**: The `TResponse` class for easily constructing HTTP responses (HTML, JSON, files, streams).
- **src/GJWTManager.pas**: A manager for creating and validating JWTs (HS256).
- **src/OverlappedExPool.pas**: An object pool for OVERLAPPED structures to optimize performance.
- **src/WinApiAdditions.pas**: Definitions of WinAPI constants, types, and functions needed for SChannel and IOCP handling.

## Configuration

The main server parameters can be configured in the `GHttpsIOCPSvr.dpr` file when creating an instance of the `TGHttpsServerIOCP` object:

```delphi
var Server := TGHttpsServerIOCP.Create(
    8443,                   // Port
    'localhost',            // Certificate Subject Name (CN)
    'GHttpsIOCPSvr',        // Certificate Store Name
    'YourSuperSecretKey...',// JWT signing key
    2000,                   // Maximum connections
    275,                    // Maximum requests per second
    ...
);
```

## License

This project is licensed under the MIT License. Details can be found in the source files.

**Copyright (c) 2025 GECKO-71**
