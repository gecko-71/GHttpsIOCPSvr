# GHttpsServerIOCP - A High-Performance HTTPS Server in Delphi

This project is an implementation of an asynchronous, multi-threaded HTTPS server for Windows, written in Delphi. The server utilizes I/O Completion Ports (IOCP) and the native Windows TLS/SSL stack (SChannel), ensuring high performance, scalability, and security.

It serves as an excellent starting point for building your own efficient REST APIs, web services, or other applications that require handling a large number of concurrent HTTPS connections.

## Key Features

*   **High Performance and Scalability:** Built on I/O Completion Ports (IOCP), allowing for the efficient handling of thousands of concurrent connections using a small pool of worker threads.
*   **Native Windows SSL/TLS:** Uses SChannel, eliminating the need for external libraries like OpenSSL. It supports modern protocols (TLS 1.2, TLS 1.3) and ciphers.
*   **Security:**
    *   Integrated **JWT (JSON Web Token)** manager for endpoint authorization (Bearer Token).
    *   Advanced request parsing with built-in validation mechanisms to protect against attacks.
*   **Modern API:**
    *   Support for large file uploads (`multipart/form-data`).
    *   Streaming of large file downloads.
    *   A simple routing system for registering endpoints.
*   **Resource Management:**
    *   A built-in monitor thread that protects the server from overload (CPU, memory, requests per second).
    *   A pool of `OverlappedEx` objects to minimize memory allocation.
    *   Utilizes the **FastMM5** memory manager.
*   **Logging:** Integrated logging system based on `Quick.Logger` with output to the console and files.

## Requirements

*   **Delphi:** Version 10.4 Sydney or newer.
*   **Operating System:** Windows.
*   **Dependencies:**
    *   [QuickLogger](https://github.com/exilon/QuickLogger)
    *   [FastMM5](https://github.com/pleriche/FastMM5)

## Getting Started: How to Run

Follow these steps to get the server up and running on your local machine.

### 1. Clone the Repository
```bash
git clone [YOUR_REPOSITORY_URL]
cd [DIRECTORY_NAME]
```

### 2. Configure Dependencies in Delphi
1.  Open Delphi.
2.  Go to `Tools > Options > Language > Delphi > Library`.
3.  In the "Library path" field, add the paths to the source directories of `QuickLogger` and `FastMM5`.

### 3. Generate a Self-Signed SSL Certificate
The server requires an SSL certificate for HTTPS. For local development, you can generate a self-signed one.

1.  Open a Command Prompt (CMD) **as an Administrator**.
2.  Run the following command:
    ```bash
    MakeCert.exe -r -pe -n "CN=localhost" -ss GHttpsIOCPSvr -a sha256 -sky exchange -sp "Microsoft Enhanced RSA and AES Cryptographic Provider" -sy 24
    ```
    **Note:** The certificate store name (`-ss GHttpsIOCPSvr`) **must** match the name specified in the server's code (`'GHttpsIOCPSvr'`).

### 4. Build and Run the Project
1.  Open the `GHttpsIOCPSvr.dpr` file in Delphi.
2.  Build the project (`Ctrl+F9`).
3.  Run the project (`F9`).

The server will start on port **8443**. The console will display logs indicating the server's status.

## Building Your Application: The Core Structure

All server logic resides within the main `program` block. Here is the fundamental structure for creating, configuring, and running the server, as seen in `GHttpsIOCPSvr.dpr`.

```delphi
program GHttpsIOCPSvr;

{$APPTYPE CONSOLE}
// ... uses clause ...

begin
  // (Logger and other initial setup)
  try
    // 1. CREATE THE SERVER INSTANCE
    // Parameters: Port, Certificate CN, Certificate Store Name
    var Server := TGHttpsServerIOCP.Create(8443, 'localhost', 'GHttpsIOCPSvr');
    try
      // 2. REGISTER YOUR ENDPOINTS HERE
      // (See examples in the next section)
      // Server.RegisterEndpointProc('/hello', hmGET, ...);
      // Server.RegisterEndpointProc('/api/data', hmGET, ...);


      // 3. START THE SERVER
      Server.Start;
      Logger.Info('Server running. Press Enter to stop...');
      Readln; // Wait for user input to stop

      // 4. STOP THE SERVER CLEANLY
      Server.Stop;
    finally
      Server.Free;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Fatal Error: ' + E.Message);
      Readln;
    end;
  end;
end.
```

## Endpoint Registration Examples

You register your endpoints inside the `try...finally` block, after creating the server instance and before calling `Server.Start`. Here are common patterns.

### Example 1: Simple Text Response
This is a basic "Hello, World!" endpoint.

**Delphi Code:**
```delphi
Server.RegisterEndpointProc('/hello', hmGET,
  procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
  begin
    AResponse.AddTextContent('text/plain', 'Hello, World!');
  end
);
```
**Test with curl:**
```bash
curl -k https://localhost:8443/hello
```

### Example 2: Returning JSON Content
This example creates and returns a `TJSONObject`.

**Delphi Code:**
```delphi
uses System.JSON;
...
Server.RegisterEndpointProc('/api/data', hmGET,
  procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
  var
    Json: TJSONObject;
  begin
    Json := TJSONObject.Create;
    try
      Json.AddPair('id', TJSONNumber.Create(123));
      Json.AddPair('name', TJSONString.Create('Test Product'));
      Json.AddPair('active', TJSONTrue.Create);
      AResponse.AddJSONContent(Json.ToJSON);
    finally
      Json.Free;
    end;
  end
);
```
**Test with curl:**
```bash
curl -k https://localhost:8443/api/data
```

### Example 3: Reading Query Parameters
This endpoint reads an `id` parameter from the URL query string.

**Delphi Code:**
```delphi
Server.RegisterEndpointProc('/api/user', hmGET,
  procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
  var
    UserId: string;
  begin
    UserId := ARequest.RequestInfo.QueryParameters.GetValueOrDefault('id', 'not_found');
    AResponse.AddTextContent('text/plain', 'User ID requested: ' + UserId);
  end
);
```
**Test with curl:**
```bash
curl -k "https://localhost:8443/api/user?id=456"
```

### Example 4: Creating a Protected Endpoint (JWT)
To protect an endpoint, simply add `atJWTBearer` as the final parameter. The server will automatically validate the token before executing your handler.

**Delphi Code:**
```delphi
Server.RegisterEndpointProc('/api/secure/data', hmGET,
  procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
  begin
    AResponse.AddTextContent('text/plain', 'This is a secret message!');
  end,
  atJWTBearer // <-- This makes the endpoint require a valid JWT token
);
```
**Test with curl:**
```bash
# First, get a token from /login. Then, use the access_token here.
TOKEN="YOUR_TOKEN"
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/secure/data
```

---

## Endpoints in the Demo Application

The main `GHttpsIOCPSvr.dpr` file includes the following pre-configured endpoints for demonstration.

| Method | Path        | Authorization | Description                                                                 |
|--------|-------------|---------------|-----------------------------------------------------------------------------|
| `GET`  | `/`         | None          | Shows a welcome HTML page.                                                  |
| `POST` | `/login`    | None          | Authenticates with `admin`/`password123` to get a JWT.                      |
| `GET`  | `/echo`     | None          | Echoes back URL query parameters in an HTML page.                           |
| `POST` | `/echojson` | **JWT**       | Protected endpoint. Echoes back the JSON body it receives.                  |
| `GET`  | `/large`    | None          | Streams a large 10MB file from the server disk.                             |
| `POST` | `/upload`   | None          | Handles `multipart/form-data` file uploads. Saves files to `./uploads/`.   |


## Project Structure

*   `GHttpsIOCPSvr.dpr`: The main project file and application entry point.
*   `src/GHttpsServerIOCP.pas`: The core server class.
*   `src/GRequest.pas`, `GRequestBody.pas`: Request parsing and handling.
*   `src/GResponse.pas`: Response construction.
*   `src/GJWTManager.pas`: JWT creation and validation.
*   `src/OverlappedExPool.pas`: `OVERLAPPED` object pool for performance.
*   `src/WinApiAdditions.pas`: WinAPI definitions for SChannel and IOCP.

## License

This project is licensed under the **MIT License**. Details can be found in the source files.

Copyright (c) 2025 GECKO-71
