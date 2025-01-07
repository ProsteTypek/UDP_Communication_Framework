#pragma comment(lib, "ws2_32.lib")
#include "stdafx.h"
#include <winsock2.h>
#include "ws2tcpip.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <cstring> // For memcpy


#define SENDER
//#define RECEIVER

//#define NDERP_NOT_USED
#define NDERP_USED

#define BUFFERS_LEN 1024
#define DEFAULT_WINDOW_SIZE 5
#define SAVEPATH_RECIEVER "recieved_files"; // Ensure this directory exists
#define FILE_PATH_SENDER "test_files\\tabule.jpg"
//#define FILE_PATH_SENDER "test_files\\dddddddddddddddddddddddddddddddddddddd.mp4"

#ifdef NDERP_NOT_USED

#define TARGET_IP "127.0.0.1"

#ifdef SENDER
#define TARGET_PORT 5100
#define LOCAL_PORT 5300
#endif

#ifdef RECEIVER
#define TARGET_PORT 5300
#define LOCAL_PORT 5100
#endif

#endif

#ifdef NDERP_USED
#define TARGET_IP "127.0.0.1"

#ifdef SENDER
#define TARGET_PORT 14000
#define LOCAL_PORT 15001
#endif

#ifdef RECEIVER
#define TARGET_PORT 14001
#define LOCAL_PORT 15000
#endif

#endif

std::mutex ackMutex;
std::vector<bool> ackReceived;


struct Packet {
    uint32_t sequenceNumber;       // Sequence number of the packet
    uint32_t crc;
    uint32_t dataLength;// CRC checksum for the data
    char data[BUFFERS_LEN - 12];    // Payload (1024 - 12 = 1016 bytes for data)
};

void InitWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        exit(1);
    }
}

// Helper function to extract the file name from a file path without using <filesystem>
std::string ExtractFileName(const std::string& filePath) {
    size_t lastSlash = filePath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        return filePath.substr(lastSlash + 1);
    }
    return filePath; // If no slash is found, the entire path is the file name
}

uint32_t CalculateCRC(const Packet& packet) {
    uint32_t crc = 0xFFFFFFFF;

    // sequencenumber CRC
    const uint32_t sequenceNumberNet = htonl(packet.sequenceNumber);
    const char* seqBytes = reinterpret_cast<const char*>(&sequenceNumberNet);
    for (size_t i = 0; i < sizeof(sequenceNumberNet); ++i) {
        crc ^= static_cast<uint8_t>(seqBytes[i]);
        for (int j = 0; j < 8; ++j) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
        }
    }

    // datalength CRC
    const uint32_t dataLengthNet = htonl(packet.dataLength);
    const char* lengthBytes = reinterpret_cast<const char*>(&dataLengthNet);
    for (size_t i = 0; i < sizeof(dataLengthNet); ++i) {
        crc ^= static_cast<uint8_t>(lengthBytes[i]);
        for (int j = 0; j < 8; ++j) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
        }
    }

    // data CRC
    for (size_t i = 0; i < packet.dataLength; ++i) {
        crc ^= static_cast<uint8_t>(packet.data[i]);
        for (int j = 0; j < 8; ++j) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
        }
    }

    return ~crc;
}



void SendData(SOCKET socketS, sockaddr_in & addrDest, const std::string & filePath, size_t windowSize) {
    std::ifstream file(filePath, std::ios::binary);
    std::cout << "file_path: " << filePath << std::endl;
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file." << std::endl;
        return;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Extract the file name from the path
    std::string fileName = ExtractFileName(filePath);
    std::cout << "Sending file: " << fileName << ", Size: " << fileSize << " bytes" << std::endl;

    ackReceived.resize((fileSize + BUFFERS_LEN - 13) / (BUFFERS_LEN - 12), false);


    // START packet inicialization 
    Packet startPacket;
    startPacket.sequenceNumber = htonl(0); // Sequence number for START packet = 0

    // Filling the START packet
    std::string startData = "START:" + fileName + ":" + std::to_string(fileSize);
    startPacket.dataLength = static_cast<uint32_t>(startData.size());
    memcpy(startPacket.data, startData.c_str(), startPacket.dataLength);

    // Calculate CRC for packet
    startPacket.crc = htonl(CalculateCRC(startPacket));

    // Sending START packet
    char start_buffer[BUFFERS_LEN];
    memcpy(start_buffer, &startPacket, sizeof(Packet));
    sendto(socketS, start_buffer, startPacket.dataLength + 12, 0, (sockaddr*)&addrDest, sizeof(addrDest));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::cout << "Sent START packet with sequence number 0 and data: " << startData << std::endl;

    bool startAckReceived = false;
    while (!startAckReceived) {
        // Send start packet
        sendto(socketS, (char*)&startPacket, sizeof(startPacket), 0, (sockaddr*)&addrDest, sizeof(addrDest));

        char ackBuffer[16];
        sockaddr_in from;
        int fromLen = sizeof(from);
        int bytesReceived = recvfrom(socketS, ackBuffer, sizeof(ackBuffer), 0, (sockaddr*)&from, &fromLen);
        //std::cout << "Ackbuffer" << std::string(ackBuffer) << std::endl;
        //std::cout << "Ackbuffer size" << std::size(ackBuffer) << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (bytesReceived > 0 && strncmp(ackBuffer, "START_ACK", 9) == 0) {
            startAckReceived = true;
            std::cout << "Start acknowledgment received." << std::endl;
        }
        else {
            std::cout << "Resending START packet..." << std::endl;
        }
    }



    uint32_t offset = 0;
    size_t totalPackets = (fileSize + BUFFERS_LEN - 13) / (BUFFERS_LEN - 12);

    while (offset < totalPackets) {
        // Send packets in the window
        for (size_t i = 0; i < windowSize && offset + i < totalPackets; ++i) {
            if (ackReceived[offset + i]) {
                continue;
            }

            Packet packet;
            memset(packet.data, 0, sizeof(packet.data));
            packet.sequenceNumber = htonl(offset + i);

            // Calculate the position in the file based on sequence number
            size_t position = (offset + i) * (BUFFERS_LEN - 12);
            if (position >= fileSize) {
                std::cerr << "Attempting to read beyond EOF. Sequence: " << (offset + i) << std::endl;
            }

            // Clear any error state before seeking or reading
            if (!file) {
                file.clear(); // Clear error flags
            }

            // Calculate remaining bytes to read
            size_t remainingBytes = fileSize - position;
            size_t bytesToRead = (sizeof(packet.data) < remainingBytes) ? sizeof(packet.data) : remainingBytes;

            // Seek to the correct position and read data
            file.seekg(position);
            //file.seekg((offset + i) * (BUFFERS_LEN - 12));
            size_t bytesRead = file.read(packet.data, sizeof(packet.data)) ? sizeof(packet.data) : file.gcount();
            packet.dataLength = static_cast<uint32_t>(bytesRead);

			uint32_t crc = CalculateCRC(packet);
            packet.crc = htonl(crc);

            char buffer[BUFFERS_LEN];
            memcpy(buffer, &packet, sizeof(packet));
            sendto(socketS, buffer, bytesRead + 12, 0, (sockaddr*)&addrDest, sizeof(addrDest));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            std::cout << "--------------------------------------------------------------------------" << std::endl;
            std::cout << "Sent packet: " << offset + i << std::endl;
            std::cout << "CRC: " << crc << std::endl;
            std::cout << "Send packet length " << packet.dataLength << std::endl;
        }


        // Wait for acknowledgments
        for (size_t i = 0; i < windowSize && offset + i < totalPackets; ++i) {
            if (!ackReceived[offset + i]) {
                char ackBuffer[16];
                sockaddr_in from;
                int fromLen = sizeof(from);
                int bytesReceived = recvfrom(socketS, ackBuffer, sizeof(ackBuffer), 0, (sockaddr*)&from, &fromLen);

                //std::cout << "Received acknowledgment raw data: " << std::string(ackBuffer, bytesReceived) << std::endl;
                //std::cout << "Acknowledgment size: " << bytesReceived << std::endl;

                if (bytesReceived > 0 && strncmp(ackBuffer, "ACK", 3) == 0) {
                    uint32_t ackSequence = ntohl(*(uint32_t*)(ackBuffer + 3));

                    //std::cout << "ACK Sequence (text): " << ackBuffer + 3 << std::endl;
                    //std::cout << "ACK Sequence (decoded): " << ackSequence << std::endl;
                    //std::cout << "ACK Vector Size: " << ackReceived.size() << std::endl;

                    if (ackSequence < ackReceived.size()) {
                        std::lock_guard<std::mutex> lock(ackMutex);
                        ackReceived[ackSequence] = true;
                        std::cout << "Acknowledged packet: " << ackSequence << std::endl;
                    }
                    else {
                        std::cerr << "Acknowledgment sequence out of range: " << ackSequence << std::endl;
                    }
                }
            }
        }

        // Move window only if all packets in the current window are acknowledged
        bool allAcked = true;
        for (size_t i = 0; i < windowSize && offset + i < totalPackets; ++i) {
            if (!ackReceived[offset + i]) {
                allAcked = false;
                break;
            }
        }

        if (allAcked) {
            offset += windowSize;
        }
    }

    // Send stop packet
    Packet stopPacket;
    stopPacket.sequenceNumber = htonl(0xFFFFFFFF); // Use a reserved sequence number for STOP
    std::string stopMessage = "STOP";
    stopPacket.dataLength = static_cast<uint32_t>(stopMessage.size());
    memcpy(stopPacket.data, stopMessage.c_str(), stopPacket.dataLength);
    stopPacket.crc = htonl(CalculateCRC(stopPacket));

    char stop_buffer[BUFFERS_LEN];
    memcpy(stop_buffer, &stopPacket, sizeof(Packet));

    bool stopAckReceived = false;
    auto startTime = std::chrono::steady_clock::now();

    while (!stopAckReceived) {
        // Check elapsed time
        auto elapsedTime = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsedTime).count() >= 3) {
            std::cout << "Timeout reached. Exiting STOP acknowledgment loop." << std::endl;
            break;
        }

        // Send STOP packet
        sendto(socketS, stop_buffer, stopPacket.dataLength + 12, 0, (sockaddr*)&addrDest, sizeof(addrDest));

        // Wait for acknowledgment
        char ackBuffer[16];
        sockaddr_in from;
        int fromLen = sizeof(from);
        int bytesReceived = recvfrom(socketS, ackBuffer, sizeof(ackBuffer), 0, (sockaddr*)&from, &fromLen);

        if (bytesReceived > 0 && strncmp(ackBuffer, "STOP_ACK", 8) == 0) {
            stopAckReceived = true;
            std::cout << "Stop acknowledgment received." << std::endl;
        }
        else {
            std::cout << "Resending STOP packet..." << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }



    file.close();
    std::cout << "File sent successfully." << std::endl;
}


void ReceiveData(SOCKET socketS, sockaddr_in& addrDest) {
    int addrDestLen = sizeof(addrDest);
    char buffer[BUFFERS_LEN];
    std::ofstream outFile;
    bool receiving = false;
    std::string fileName;
    size_t expectedFileSize = 0;

    while (true) {
        int bytesReceived = recvfrom(socketS, buffer, BUFFERS_LEN, 0, nullptr, nullptr);
        if (bytesReceived <= 0) continue;

        Packet receivedPacket;
        memset(receivedPacket.data, 0, sizeof(receivedPacket.data));

        memcpy(&receivedPacket, buffer, bytesReceived);

        uint32_t receivedCRC = ntohl(receivedPacket.crc);
        uint32_t calculatedCRC = CalculateCRC(receivedPacket);

        std::cout << "--------------------------------------------------------------------------" << std::endl;
        std::cout << "Received crc" << receivedCRC << std::endl;
        std::cout << "Calculated crc" << calculatedCRC << std::endl;

        if (receivedCRC == calculatedCRC) {
            if (strncmp(receivedPacket.data, "START:", 6) == 0) {
                std::string startData(receivedPacket.data, receivedPacket.dataLength);
                size_t firstColon = startData.find(':');
                size_t secondColon = startData.find(':', firstColon + 1);

                fileName = startData.substr(firstColon + 1, secondColon - firstColon - 1);
                expectedFileSize = std::stoull(startData.substr(secondColon + 1));

                std::string savePath = SAVEPATH_RECIEVER;
                //outFile.open(savePath + fileName, std::ios::binary | std::ios::out);

                std::cout << "Receiving state:  " << receiving << std::endl;
                if (!receiving) {
                    outFile.open(savePath + fileName, std::ios::binary | std::ios::out);
                    std::cout << " file opened: " << savePath + fileName << std::endl;
                }


                std::cout << "Receiver START data: " << std::string(receivedPacket.data, bytesReceived - 12) << std::endl;

                std::cout << "START_ACK sent. Receiving file: " << fileName << " (" << expectedFileSize << " bytes)" << std::endl;

                if (!outFile.is_open()) {
                    std::cerr << "Error opening file for writing." << std::endl;

                }

                sendto(socketS, "START_ACK", 9, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                receiving = true;
                continue;
            }

            else if (strncmp(receivedPacket.data, "STOP", 4) == 0) {
                for (size_t i = 0; i < 5; i++)
                {
                    sendto(socketS, "STOP_ACK", 8, 0, (sockaddr*)&addrDest, addrDestLen);
                }
                std::cout << "Received valid STOP packet." << std::endl;

                std::cout << "File transfer complete." << std::endl;
                break;
            }


            else if (receiving && receivedPacket.dataLength > 0) {
                if (!outFile.is_open()) {
                    std::cout << "Error opening file for writing." << std::endl;
                }
                else
                {
                    std::cout << "File opened for writing." << std::endl;
                }


                uint32_t sequenceNumber = ntohl(receivedPacket.sequenceNumber);

                outFile.seekp(sequenceNumber * (BUFFERS_LEN - 12));
                if (!outFile) {
                    std::cerr << "Error: seekp() failed for sequence " << ntohl(receivedPacket.sequenceNumber) << std::endl;
                    std::cerr << "seekp:  " << sequenceNumber * (BUFFERS_LEN - 12) << std::endl;

                }

                if (!outFile.write(receivedPacket.data, receivedPacket.dataLength)) {
                    std::cerr << "Error writing to file at sequence " << sequenceNumber << std::endl;

                }
                if (receivedPacket.dataLength > sizeof(receivedPacket.data)) {
                    std::cerr << "Received packet with invalid data length!" << std::endl;

                }

                char ackBuffer[7];
                memcpy(ackBuffer, "ACK", 3);
                uint32_t ackSeqNet = htonl(ntohl(receivedPacket.sequenceNumber));
                std::cout << "Recieved packet: " << ntohl(receivedPacket.sequenceNumber) << std::endl;
                std::cout << "Receive packet length " << receivedPacket.dataLength << std::endl;
                memcpy(ackBuffer + 3, &ackSeqNet, sizeof(ackSeqNet));
                sendto(socketS, ackBuffer, 7, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                std::cout << "Acknowledged packet: " << sequenceNumber << std::endl;

            }
        }
        else {
            std::cerr << "CRC mismatch for packet." << std::endl;
        }
    }
    outFile.close();
    std::cerr << "File saved" << std::endl;
}


int main() {
    SOCKET socketS;
    InitWinsock();
    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_PORT);
    local.sin_addr.s_addr = INADDR_ANY;

    socketS = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds
    timeout.tv_usec = 0; // 0 microseconds
    setsockopt(socketS, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    if (bind(socketS, (sockaddr*)&local, sizeof(local)) != 0) {
        std::cerr << "Binding error." << std::endl;
        return 1;
    }

#ifdef SENDER
    sockaddr_in addrDest;
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);
    
    std::string filePath = FILE_PATH_SENDER;
    size_t windowSize = DEFAULT_WINDOW_SIZE;
    SendData(socketS, addrDest, filePath, windowSize);
#endif

#ifdef RECEIVER
    sockaddr_in addrDest;
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);

    ReceiveData(socketS, addrDest);

#endif
    closesocket(socketS);
    WSACleanup();
    return 0;
}
