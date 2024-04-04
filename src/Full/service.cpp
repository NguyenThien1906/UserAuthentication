#include <iostream>
#include <string>
#include <sstream>
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <chrono>
#include "EncryptionUtils.h"

#define THRESHOLD_TIME 120
using namespace std;

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

    string createMessage(string serviceSessionKey) {
        return userID + "," + to_string(timestamp) + "," + serviceSessionKey;
    }
    //Q: return encrypt(message) ?
    //A - Thien: decrypt(message, serviceTicket.serviceSessionKey) from user
    //    Context: user creates this message, encrypt it with serviceSessionKey to send to Service Server.
    // then Service Server decrypts this after getting serviceSessionKey from decrypting Service Ticket.

    //Q: do i need to do anything else to this Object ?
    //A - Thien: [get to main fuction]
};

class ServiceAuthen {
private:
    string serviceID;
    int timestamp;

public:

    ServiceAuthen(const string& serviceID) {
        this->serviceID = serviceID;
        this->timestamp = Timestamp();
    }

    string getServiceID() const {
        return serviceID;
    }

    int getTimestamp() const {
        return timestamp;
    }

    void setServiceID(const string& newServiceID) {
        serviceID = newServiceID;
    }

    void setTimestamp() {
        timestamp = Timestamp();
    }
    void display() const {
        cout << "Service ID: " << serviceID << ", Timestamp: " << timestamp << endl;
    }
    string createMessage() {
        return serviceID + "," + to_string(timestamp);
    }
    //Q: return encrypt(message) ?
    //A - Thien: user would encrypt(message, serviceSecretKey) //from previous part, say it's just a random key

    //Q: do i need to do anything else to this Object ?
    //A - Thien: [get to main function]
};

//i don't know where to put these check function but i'll implement those for now.
bool checkUserid(string userIdTicket, string UAticket) {
    return userIdTicket == UAticket;
}

bool checkTime(int TicketStartTime, int UAtime) {
    //invalid if more tan 1 min (60)
    //return (UAtime - TicketEndTime) <= 60;
    return TicketStartTime == UAtime;
}

bool checkIP(string clientNetworkAddress, string senderIP) {
    return clientNetworkAddress == senderIP;
}

bool lifetimeCheck(int endTime) {
    //im assuming lifetime is current time
    auto now = chrono::system_clock::now();
    int unix_timestamp = chrono::system_clock::to_time_t(now);
    //im
    return endTime > unix_timestamp;
}
//Q: is this the right way to check timestamp ?
/*A - Thien: I really don't get what you mean by the lifetimeCheck() function,
    but here is an easy way to understand: there are two timestamp checks.

1. ServiceTicket.timestamp + ServiceTicket.lifetime > ServiceServer.time_at if yes then 
    don't have to check #2, just deny service; else check #2.
    - After some LONG time, user must enter credentials for a new ticket from the very beginning.    
2. UserAuthenticator.timestamp > ServiceTicket.timestamp + fixed delay time (120 s) if yes then 
deny service.
    - This ticket is temporarily used for SHORT service sessions.
    - If the ticket fails and #1 still false, client can renew the ticket through KDC without having to enter credentials
    such as passwords etc.
3. Accept service: ServiceAuthenticator.msg = "Hello user, [timestamp]"
   Deny service: ServiceAuthenticator.msg = "ERROR, [timestamp]"
*/
// StackOverflow: https://stackoverflow.com/questions/14682153/lifetime-of-kerberos-tickets
// Watch: https://www.youtube.com/watch?v=5N242XcKAsM&t=815s&ab_channel=DestinationCertification&t=757s


//ticket structure for reference (please check if the following structure is correct and is in the right order)
struct Ticket {
    string clientID;
    string clientNetworkAddress;
    int startTime = 0;
    int endTime = 0;
    string sessionKey;
    string serviceID;
};

Ticket parseTicket(const string& str) {
    istringstream iss(str);
    Ticket ticket;
    string token;

    getline(iss, ticket.clientID, ',');
    getline(iss, ticket.clientNetworkAddress, ',');
    getline(iss, token, ',');
    ticket.startTime = stoi(token);
    getline(iss, token, ',');
    ticket.endTime = stoi(token);
    getline(iss, ticket.sessionKey, ',');
    getline(iss, ticket.serviceID, ',');

    return ticket;
}

int main(){
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // specifying the address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVICE_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // binding socket.
    if(bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) != 0)
        printf("Service: Bind error.\n");

    // listening to the assigned socket
    listen(serverSocket, 5);

    // accepting connection request
    struct sockaddr_in clientAddress;
    socklen_t clientAddrLen = sizeof(clientAddress);
    int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddrLen);

    // receive
    char buffer[MAX_BUFFER] = {0};
    int msg_size = 0;
    recv(clientSocket, &msg_size, sizeof(int)/sizeof(char), 0); // int
    recv(clientSocket, buffer, msg_size, 0);
    string serviceTicket_en = string(buffer, msg_size);

    recv(clientSocket, &msg_size, sizeof(int)/sizeof(char), 0); // int
    recv(clientSocket, buffer, msg_size, 0);
    string UA_en = string(buffer, msg_size);

    // decrypt
    vector<string> serviceTicket_data = extractData(decrypt(serviceTicket_en, serviceSecretKey));
    string serviceSessionKey = serviceTicket_data[5];

    vector<string> UA_data = extractData(decrypt(UA_en, serviceSessionKey));

    printf("Service Ticket: %s\n", decrypt(serviceTicket_en, serviceSecretKey).data());
    printf("User Au: %s\n", decrypt(UA_en, serviceSessionKey).data());

    // check connection validity
    string serviceTicket_userID = serviceTicket_data[0];
    string UA_userID = UA_data[0];
    int serviceTicket_timestamp = strToInt(serviceTicket_data[2]);
    int UA_timestamp = strToInt(UA_data[1]);
    int serverCurrentTime = Timestamp();
    int serviceTicket_lifetime = strToInt(serviceTicket_data[4]);

    if(serviceTicket_userID != UA_userID){
        printf("Error: wrong usernames.\n");
        return 0;
    }
    if(serviceTicket_timestamp + serviceTicket_lifetime < serverCurrentTime){
        printf("Ticket lifetime out.\n");
        return 0;
    }
    if(serviceTicket_timestamp + THRESHOLD_TIME < UA_timestamp){
        printf("Session timeout.\n");
        return 0;
    }

    // encrypt Service Authenticator
    ServiceAuthen SA("serviceID");
    string SA_en = encrypt(SA.createMessage(), serviceSessionKey);

    send(clientSocket, SA_en.data(), SA_en.length(), 0);

    close(serverSocket);
    return 0;
}
