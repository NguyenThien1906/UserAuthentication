#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <chrono>
#include <vector>
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

//classes
class UA {
    string userID;
    int timestamp;

public:

    UA(string userID, int timestamp) : userID(userID), timestamp(timestamp) {}


    string getUserID() const {
        return userID;
    }
    int getTimestamp() const {
        return timestamp;
    }
    void setUserID(const string& newUserID) {
        userID = newUserID;
    }
    void setTimestamp(int newTimestamp) {
        timestamp = newTimestamp;
    }

    void display() const {
        cout << "User ID: " << userID << ", Timestamp: " << timestamp << endl;
    }

    string createMessage() {
        return userID + "," + to_string(timestamp);
    }
    string CreateEncryptMessage(string serviceSessionKey) {
        return encrypt(this->createMessage(), serviceSessionKey);
    }
};

int main() {
    WSADATA wsaData;
    SOCKET connectSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    int iResult;
    //const char* sendbuf = "Hello from client";
    char recvbuf[1024];
    int recvbuflen = 1024;

    //cl info 
    UA user("user123", 1612121212);
    //im assuming i received a ticket (string) with the same structure above and it's encrypted.
    string ticket1 = "user123,serviceABC,1618074032,52093,3600,a1b2c3d4";

    string serviceSessionKey = "a1b2c3d4";
    //serializing messasge so i could send both UA and ticket at the same time
    string serialized_message = serializeData(user.CreateEncryptMessage(serviceSessionKey))+serializeData(ticket1);


    


    // Initialize 
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Create a socket for connecting to server
    connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        std::cout << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);

    // Use InetPton instead of inet_addr
    iResult = InetPton(AF_INET, L"127.0.0.1", &serverAddr.sin_addr);


    if (iResult != 1) { // InetPton returns 1 on success
        std::cout << "InetPton failed with error: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    // Connect to server
    iResult = connect(connectSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (iResult == SOCKET_ERROR) {
        std::cout << "Connect failed with error: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }
    // Convert serialized_message to a const char* for sending

    const char* sendbuf = serialized_message.c_str();
    // Send data to server
    iResult = send(connectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        std::cout << "Send failed with error: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Bytes Sent: " << iResult << std::endl;

    // Receive data from server
    iResult = recv(connectSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0)
        std::cout << "Bytes received: " << iResult << std::endl;
    else if (iResult == 0)
        std::cout << "Connection closed" << std::endl;
    else
        std::cout << "recv failed with error: " << WSAGetLastError() << std::endl;
    std::cout << recvbuf<<endl;
    string recvMsg(recvbuf, iResult);
    cout << recvMsg<<endl;


    //test serialize message
    /*
    size_t pos = 0;
    std::string received1 = deserializeData(recvMsg, pos);
    std::string received2 = deserializeData(recvMsg, pos);
    std::cout << "Received 1: " << received1 << std::endl;
    std::cout << "Received 2: " << received2 << std::endl;
    */

    // Cleanup
    closesocket(connectSocket);
    WSACleanup();

    return 0;
}
