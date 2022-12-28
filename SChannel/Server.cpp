#include <winsock2.h>
#include <schannel.h>

#include <iostream>

int main()
{
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return 1;
    }

    // Create a socket to listen for incoming connections
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Set up the sockaddr_in structure for the listen socket
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(443);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the listen socket to the address
    result = bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Start listening for incoming connections
    result = listen(listenSocket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        std::cerr << "listen failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Accept incoming connections and set up the secure channel context
    while (true) {
        // Accept an incoming connection
        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
            continue;
        }

        // Set up the credentials for the secure channel context
        CredHandle credHandle;
        TimeStamp credExpiry;
        result = AcquireCredentialsHandle(nullptr, UNISP_NAME,
            SECPKG_CRED_INBOUND, nullptr, nullptr, nullptr, nullptr,
            &credHandle, &credExpiry);
        if (result != SEC_E_OK) {
            std::cerr << "AcquireCredentialsHandle failed: " << result << std::endl;
            closesocket(clientSocket);
            continue;
        }

        // Set up the security context for the connection
        SecBuffer outBuffers[1];
        outBuffers[0].pvBuffer = nullptr;
        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].cbBuffer = 0;
        SecBufferDesc outBufferDesc;
        outBufferDesc.cBuffers = 1;
        outBufferDesc.pBuffers = outBuffers;
        outBufferDesc.ulVersion = SECBUFFER_VERSION;
        CtxtHandle ctxtHandle;
        ULONG contextAttr;
        TimeStamp contextExpiry;
        result = AcceptSecurityContext(&credHandle, nullptr, &outBufferDesc,
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM, SECURITY_NATIVE_DREP,
            &ctxtHandle, nullptr, &contextAttr, &contextExpiry);
        if (result != SEC_E_OK && result != SEC_I_CONTINUE_NEEDED) {
            std::cerr << "AcceptSecurityContext failed: " << result << std::endl;
            FreeCredentialsHandle(&credHandle);
            closesocket(clientSocket);
            continue;
        }

        // Send the security token to the client
        result = send(clientSocket, (char*)outBuffers[0].pvBuffer,
            outBuffers[0].cbBuffer, 0);
        if (result == SOCKET_ERROR) {
            std::cerr << "send failed: " << WSAGetLastError() << std::endl;
            FreeCredentialsHandle(&credHandle);
            closesocket(clientSocket);
            continue;
        }
        LocalFree(outBuffers[0].pvBuffer);

        // Receive the client's security token and process it
        SecBuffer inBuffers[2];
        inBuffers[0].pvBuffer = nullptr;
        inBuffers[0].BufferType = SECBUFFER_TOKEN;
        inBuffers[0].cbBuffer = 0;
        inBuffers[1].pvBuffer = nullptr;
        inBuffers[1].BufferType = SECBUFFER_EMPTY;
        inBuffers[1].cbBuffer = 0;
        SecBufferDesc inBufferDesc;
        inBufferDesc.cBuffers = 2;
        inBufferDesc.pBuffers = inBuffers;
        inBufferDesc.ulVersion = SECBUFFER_VERSION;
        while (result == SEC_I_CONTINUE_NEEDED ||
            (result == SEC_E_OK && inBuffers[1].BufferType == SECBUFFER_EXTRA)) {
            // Receive the client's security token
            result = recv(clientSocket, (char*)inBuffers[0].pvBuffer,
                inBuffers[0].cbBuffer, 0);
            if (result == SOCKET_ERROR) {
                std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
                FreeCredentialsHandle(&credHandle);
                closesocket(clientSocket);
                break;
            }
            inBuffers[0].cbBuffer = result;

            // Process the received security token
			result = AcceptSecurityContext(&credHandle, &ctxtHandle, &inBufferDesc,
                ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM, SECURITY_NATIVE_DREP,
                &ctxtHandle, nullptr, &contextAttr, &contextExpiry);
            if (result != SEC_E_OK && result != SEC_I_CONTINUE_NEEDED) {
                std::cerr << "AcceptSecurityContext failed: " << result << std::endl;
                FreeCredentialsHandle(&credHandle);
                closesocket(clientSocket);
                break;
            }
        }
        if (inBuffers[0].pvBuffer) LocalFree(inBuffers[0].pvBuffer);

        // Check if the connection was successfully authenticated
        if (result == SEC_E_OK) {
            std::cout << "Secure connection established!" << std::endl;
            // Perform secure communication with the client here
        }

        // Clean up
        DeleteSecurityContext(&ctxtHandle);
        FreeCredentialsHandle(&credHandle);
        closesocket(clientSocket);
    }

    // Clean up
    WSACleanup();

    return 0;
}


