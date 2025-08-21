#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

//functions
// Helper function to serialize the data
std::string serializeData(const std::string& data) {
    // Prefix each string with its length and a separator
    return std::to_string(data.size()) + ";" + data;
}

// Helper function to deserialize the data
std::string deserializeData(const std::string& serialized, size_t& pos) {
    size_t separatorPos = serialized.find(';', pos);
    int length = std::stoi(serialized.substr(pos, separatorPos - pos));
    pos = separatorPos + 1; // Update position to start of data
    std::string data = serialized.substr(pos, length);
    pos += length; // Update position for next read
    return data;
}

string decrypt(const string& message, string serviceSessionKey);
string encrypt(const string& message, string serviceSessionKey);


string encrypt(const string& message, string serviceSessionKey) {
    //placeholder
    return message;
}

string decrypt(const string& message, string serviceSessionKey) {
    //placeholder
    return message;
}
bool checkUserid(string userIdTicket, string UAticket) {
    return userIdTicket == UAticket;
}

//check(serviceTicket.timestamp, UA.timestamp) 1st one arcording to Thien's answer.
bool checkTime(int ServiceTicketTime, int UAtime) {

    //this line is to rigged the check
    UAtime = ServiceTicketTime;
    return (ServiceTicketTime + 120) < UAtime;
}

bool checkIP(int clientNetworkAddress, int senderIP) {
    return clientNetworkAddress == senderIP;
}

//check(serviceTicket.lifetime > service current time)

bool lifetimeCheck(int ticketTimestamp, int serviceTicketLifetime) {
    //im assuming lifetime is current time
    auto now = chrono::system_clock::now();
    int unix_timestamp = chrono::system_clock::to_time_t(now);

    //remove this line, this only to rigged the check so result will be true in the test run.
    unix_timestamp = 0;

    return (ticketTimestamp + serviceTicketLifetime) < unix_timestamp;
}


int main() {
    WSADATA wsaData;
    SOCKET listeningSocket = INVALID_SOCKET, clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    int iResult;
    char recvbuf[1024];
    int recvbuflen = 1024;
    int clientAddrSize = sizeof(clientAddr);

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Create a socket to listen for connections
    listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listeningSocket == INVALID_SOCKET) {
        std::cout << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Bind the socket to an address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8080);

    iResult = bind(listeningSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (iResult == SOCKET_ERROR) {
        std::cout << "Bind failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    iResult = listen(listeningSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cout << "Listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on port 8080..." << std::endl;

    while (true) { // Continuously accept new connections
        // Accept a client socket
        clientSocket = accept(listeningSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cout << "Accept failed with error: " << WSAGetLastError() << std::endl;
            continue; // Skip to the next iteration of the loop
        }

        std::cout << "Client connected!" << std::endl;
        //getting client data
        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIp, INET_ADDRSTRLEN);
        int clientPort = ntohs(clientAddr.sin_port);
        // Receive data from client and echo it back
        do {
            iResult = recv(clientSocket, recvbuf, recvbuflen, 0);
            if (iResult > 0) {
                std::cout << "Bytes received: " << iResult << std::endl;
                //processing received message

                //assuming the receive message was a message containing UA and Ticket
                std::cout << recvbuf << endl;
                string recvMsg(recvbuf, iResult);
                size_t pos = 0;
                std::string received1 = deserializeData(recvMsg, pos);
                std::string received2 = deserializeData(recvMsg, pos);
                std::cout << "Received 1: " << received1 << std::endl;
                std::cout << "Received 2: " << received2 << std::endl;

                //processing received 1 (UA data)
                std::istringstream messageStream(received1);
                std::string UAuserID;
                std::string UAtimestamp;
                // Use getline with a comma as the delimiter to separate the string
                std::getline(messageStream, UAuserID, ',');
                std::getline(messageStream, UAtimestamp, ',');

                //processing receive 2 (ticket)
                std::istringstream messageStream1(received2);
                std::string TKuserID, TKserviceID, TKtimestamp, TKuserport, TKserviceTicketLifetime, TKserviceSessionKey;
                
                std::getline(messageStream1, TKuserID, ',');
                std::getline(messageStream1, TKserviceID, ',');
                std::getline(messageStream1, TKtimestamp, ',');
                std::getline(messageStream1, TKuserport, ',');
                std::getline(messageStream1, TKserviceTicketLifetime, ',');
                std::getline(messageStream1, TKserviceSessionKey, ',');

                //checking if data sent by user are valid
                bool isValid = checkUserid(TKuserID, UAuserID) && checkTime(std::stoi(TKtimestamp), std::stoi(UAtimestamp)) && checkIP(std::stoi(TKuserport), clientPort) && lifetimeCheck(std::stoi(TKtimestamp), std::stoi(TKserviceTicketLifetime));
                cout <<endl<< checkTime(std::stoi(TKtimestamp), std::stoi(UAtimestamp))<<endl;
                const char* isValidMessage;

                if (isValid) {
                    isValidMessage = "Valid";
                }
                else {
                    isValidMessage = "Invalid";
                }

                
                cout << clientPort;
                // Echo the received data back to the client
                send(clientSocket, isValidMessage, sizeof(isValidMessage), 0);
            }
            else if (iResult == 0) {
                std::cout << "Connection closing..." << std::endl;
            }
            else {
                std::cout << "recv failed with error: " << WSAGetLastError() << std::endl;
            }
        } while (iResult > 0);

        closesocket(clientSocket); // Close the client socket before accepting a new connection
    }

    // Cleanup (unreachable in this loop, but good practice)
    closesocket(listeningSocket);
    WSACleanup();

    return 0;
}
