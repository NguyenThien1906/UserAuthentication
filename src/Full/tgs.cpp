#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "EncryptionUtils.h"
#include <vector>
#include <sstream>
#include <random>

using namespace std;

// user format
const string USER[5] = {"user1", "user2", "user3", "user4", "user5"};

class tgsRes
{ // encrypted with TGS session key
public:
    string serviceID;
    int timestamp; //(UNIX, second)
    int tgsLifetime;
    string serviceSessionKey;

    string convertMessage()
    {
        return serviceID + "," + to_string(timestamp) + "," + to_string(tgsLifetime) + "," + serviceSessionKey;
    }
};

class ServiceTicket {
public:
    string userID;
	string serviceID;
	int timestamp;
	int userPort;
	int serviceTicketLifetime;
	string serviceSessionKey;

    string convertMessage() {
        return userID + "," + serviceID + "," + to_string(timestamp) + "," + to_string(userPort) + "," + to_string(serviceTicketLifetime) + "," + serviceSessionKey;
    }
};
/*
int generateTgsLifetime(int &ticketLifetime)
{
    time_t now = time(nullptr);
    return now + ticketLifetime;
}*/

string generateServiceSessionKey(int length) {
    // define characters for the service session key
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    // seed the random number generator
    random_device rd;
    mt19937 generator(rd());

    // define a distribution for selecting characters
    uniform_int_distribution<int> distribution(0, charset.size() - 1);

    // generate the service session key
    string key;
    for (int i = 0; i < length; i++) {
        key += charset[distribution(generator)];
    }

    return key;
}

vector<string> splitFields(const string& str) {
    vector<string> fields;
    stringstream ss(str);
    string field;
    while (getline(ss, field, ','))
    {
        fields.push_back(field);
    }
    return fields;
}

bool validateRequest(const string &decryptedUA, const string &decryptedTGT)
{
    vector<string> uaFields = splitFields(decryptedUA);
    vector<string> tgtFields = splitFields(decryptedTGT);

    const int expectedUAField = 2;
    const int expectedTGTField = 6;
    if (uaFields.size() != expectedUAField)
    {
        cerr << "Authentication failed: Invalid number of fields in User Authentication\n";
        return false;
    }
    if (tgtFields.size() != expectedTGTField) 
    {
        cerr << "Authentication failed: Invalid number of fields in Ticket Granting Ticket\n";
        return false;
    }

    if (uaFields[0] != tgtFields[0]) 
    {
        cerr << "Authentication failed: userID is not valid\n";
    }

    return true;
}

void receiveAndSendMsg()
{
    int port = TGS_PORT;
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // specifying the address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // binding socket.
    if(bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) != 0)
        printf("TGS: Bind error.\n");

    // listening to the assigned socket
    listen(serverSocket, 5);

    // accepting connection request
    struct sockaddr_in clientAddress;
    socklen_t clientAddrLen = sizeof(clientAddress);
    int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddrLen);

    // recieving data
    char tgtBuffer[1024] = {0};
    char reqBuffer[1024] = {0};
    char uaBuffer[1024] = {0};

    recv(clientSocket, tgtBuffer, 1024, 0);
    recv(clientSocket, reqBuffer, 1024, 0);
    recv(clientSocket, uaBuffer, 1024, 0);

    // decrypt tgt to get TGS session key
    string decryptedTGT = decrypt(string(tgtBuffer), tgsSecretKey);

    // split fields request message fields and TGT message fields (TGT is decrypted)
    vector<string> reqFields = splitFields(reqBuffer);
    vector<string> tgtFields = splitFields(decryptedTGT);

    // decrypt UA using TGS session key
    string decryptedUA = decrypt(string(uaBuffer), tgtFields[5]);

    // split UA fields (after decrypted)
    vector<string> uaFields = splitFields(decryptedUA);

    // validate request
    bool isAuthenticated = validateRequest(decryptedUA, decryptedTGT);
    if (!isAuthenticated) {
        cerr << "Authentication failed";
        close(serverSocket);
        return;
    }

    // initial tgsRes and Service Ticket
    tgsRes res;
    ServiceTicket st;
    
    // set value for TGS response
    string serviceSessionKey = generateServiceSessionKey(12);
    int ticketLifetime = stoi(reqFields[1]); 
    //int timestamp = generateTgsLifetime(ticketLifetime);
    res.serviceID = reqFields[0];
    res.timestamp = Timestamp();
    res.tgsLifetime = ticketLifetime;
    res.serviceSessionKey = serviceSessionKey;
    string resMsg = res.convertMessage();

    // set value for Service Ticket
    int userPort = stoi(tgtFields[3]);
    st.serviceID = reqFields[0];
    st.userID = uaFields[0];
    st.timestamp = Timestamp();
    // st.userPort = ntohs(clientAddress.sin_port);
    st.userPort = userPort;
    st.serviceSessionKey = serviceSessionKey;
    st.serviceTicketLifetime = ticketLifetime;
    string stMsg = st.convertMessage();

    cout << resMsg << "\n" << stMsg << "\n";

    string resMsgCipher = encrypt(resMsg, tgtFields[5]);
    string stMsgCipher = encrypt(stMsg, serviceSecretKey);

    // cout << resMsgCipher << "\n" << stMsgCipher << "\n";
    // const char* msg[] = {resMsgCipher.c_str(), stMsgCipher.c_str()};

    // for (int i = 0; i < 2; i++) {
    //     send(clientSocket, msg[i], strlen(msg[i]), 0);
    //     sleep(1);
    // }
    send(clientSocket, resMsgCipher.data(), resMsgCipher.length(), 0);
    sleep(1); // bruh
    send(clientSocket, stMsgCipher.data(), stMsgCipher.length(), 0);


    close(clientSocket);
    close(serverSocket);
}

int main()
{
    receiveAndSendMsg();
    // cout << "Message from client: \n" << msg[0] << "\n" << msg[1] << "\n" << msg[2] << "\n";
    // decrypt tgt using its secret key

    return 0;
}