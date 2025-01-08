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
#include <iomanip>
#include <iterator>
#include <array>
#include <numeric>
#include <set>

#define SENDER
//#define RECEIVER

//#define NDERP_NOT_USED
#define NDERP_USED

#define BUFFERS_LEN 1024
#define DEFAULT_WINDOW_SIZE 5
#define SAVEPATH_RECIEVER "recieved_files"; // Ensure this directory exists
//#define FILE_PATH_SENDER "test_files\\cvut_logo_testing_.png"
#define FILE_PATH_SENDER "test_files\\cat-219662_1280.bmp"
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


template<uint32_t poly>
struct crc32_table_generator {
private:
    template<typename T, bool flag>
    struct denominator;

    template<typename T>
    struct denominator<T, true>
    {
        static constexpr T value = poly;
    };

    template<typename T>
    struct denominator<T, false>
    {
        static constexpr T value = 0;
    };

    template<uint8_t index, uint8_t N = 8>
    struct crc32_table_elem {
        static constexpr bool carry =
            static_cast<bool>(crc32_table_elem<index, N - 1>::value & 0x80000000);
        static constexpr uint32_t value =
            (crc32_table_elem<index, N - 1>::value << 1) ^ denominator<uint32_t, carry>::value;
    };

    template<uint8_t index>
    struct crc32_table_elem<index, 0> {
        static constexpr uint32_t value = (index << 24);
    };

    template<size_t N = 255, uint32_t ...Indices>
    struct array_impl {
        static constexpr auto value = array_impl<N - 1, crc32_table_elem<N>::value, Indices...>::value;
    };

    template<uint32_t ...Indices>
    struct array_impl<0, Indices...> {
        static constexpr std::array<uint32_t, sizeof...(Indices) + 1> value
            = { {crc32_table_elem<0>::value, Indices...} };
    };

public:
    static constexpr std::array<uint32_t, 256> value = array_impl<>::value;
};


static const uint32_t IEEE8023_CRC32_POLYNOMIAL = 0x04C11DB7UL;


template<uint32_t poly, typename iterator_t>
static inline uint32_t crc32(uint32_t crc, const iterator_t head, const iterator_t tail)
{
    // instantiate crc32 table (compilie-time)
    static const auto crc32_table = crc32_table_generator<poly>::value;

    // calculate crc32 checksum for each byte
    return std::accumulate(head, tail, crc, [](const uint32_t& crc, const uint8_t& x) -> uint32_t {
        return (crc << 8) ^ crc32_table[((crc >> 24) ^ x) & 0xFF];
        });
}



uint32_t CalculateCRC(const Packet& packet) {
    // Create a vector containing the data to calculate CRC
    std::vector<uint8_t> data;

    // Add sequence number (big-endian)
    uint32_t sequenceNumberNet = htonl(packet.sequenceNumber);
    uint8_t* seqBytes = reinterpret_cast<uint8_t*>(&sequenceNumberNet);
    data.insert(data.end(), seqBytes, seqBytes + sizeof(sequenceNumberNet));

    // Add data length (big-endian)
    uint32_t dataLengthNet = htonl(packet.dataLength);
    uint8_t* lengthBytes = reinterpret_cast<uint8_t*>(&dataLengthNet);
    data.insert(data.end(), lengthBytes, lengthBytes + sizeof(dataLengthNet));

    // Add actual data
    data.insert(data.end(), packet.data, packet.data + packet.dataLength);

    // Initial CRC value
    uint32_t initialCRC = 0xFFFFFFFF;

    // Calculate CRC using the `crc32` function
    uint32_t crc = crc32<IEEE8023_CRC32_POLYNOMIAL>(initialCRC, data.begin(), data.end());

    // Final XOR
    return crc ^ 0xFFFFFFFF;
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
    std::vector<char> fileBuffer;  // Declare the buffer outside the if statement

    std::set<uint32_t> receivedSequences;
    std::set<uint32_t> writtenPackets;

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
            if (strncmp(receivedPacket.data, "START:", 6) == 0 && !receiving) {
                std::string startData(receivedPacket.data, receivedPacket.dataLength);
                size_t firstColon = startData.find(':');
                size_t secondColon = startData.find(':', firstColon + 1);

                fileName = startData.substr(firstColon + 1, secondColon - firstColon - 1);
                expectedFileSize = std::stoull(startData.substr(secondColon + 1));

                std::string savePath = SAVEPATH_RECIEVER;
                //outFile.open(savePath + fileName, std::ios::binary | std::ios::out);

                fileBuffer.resize(expectedFileSize, 0);


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

                //// Pre-allocate file size
                //outFile.seekp(expectedFileSize - 1); // Move to the last byte
                //outFile.write("", 1);               // Write a single byte to allocate space
                //outFile.seekp(0);                   // Reset to the beginning of the file

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



                uint32_t sequenceNumber = ntohl(receivedPacket.sequenceNumber);
                size_t offset = sequenceNumber * (BUFFERS_LEN - 12);

                if (writtenPackets.find(sequenceNumber) != writtenPackets.end()) {
                    std::cout << "Duplicate packet ignored: Seq = " << sequenceNumber << std::endl;
                    char ackBuffer[7];
                    memcpy(ackBuffer, "ACK", 3);
                    uint32_t ackSeqNet = htonl(ntohl(receivedPacket.sequenceNumber));
                    std::cout << "Recieved packet: " << ntohl(receivedPacket.sequenceNumber) << std::endl;
                    std::cout << "Receive packet length " << receivedPacket.dataLength << std::endl;

                    memcpy(fileBuffer.data() + offset, receivedPacket.data, receivedPacket.dataLength);


                    memcpy(ackBuffer + 3, &ackSeqNet, sizeof(ackSeqNet));
                    sendto(socketS, ackBuffer, 7, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                    std::cout << "Acknowledged packet: " << sequenceNumber << std::endl;
                    continue;
                }


                if (!outFile.is_open()) {
                    std::cout << "Error opening file for writing." << std::endl;
                }
                else
                {
                    std::cout << "File opened for writing." << std::endl;
                }

                if (offset + receivedPacket.dataLength > expectedFileSize) {
                    std::cerr << "Error: Packet offset exceeds allocated file size!" << std::endl;
                    continue;
                }

                std::cout << "Packet written: Seq = " << sequenceNumber
                    << ", Offset = " << offset
                    << ", Length = " << receivedPacket.dataLength << std::endl;

                if (!outFile) {
                    std::cerr << "Error: seekp() failed for sequence " << ntohl(receivedPacket.sequenceNumber) << std::endl;
                    std::cerr << "seekp:  " << sequenceNumber * (BUFFERS_LEN - 12) << std::endl;

                }

                /*if (!outFile.write(receivedPacket.data, receivedPacket.dataLength)) {
                    std::cerr << "Error writing to file at sequence " << sequenceNumber << std::endl;

                }*/


                if (receivedPacket.dataLength > sizeof(receivedPacket.data)) {
                    std::cerr << "Received packet with invalid data length!" << std::endl;

                }


                char ackBuffer[7];
                memcpy(ackBuffer, "ACK", 3);
                uint32_t ackSeqNet = htonl(ntohl(receivedPacket.sequenceNumber));
                std::cout << "Recieved packet: " << ntohl(receivedPacket.sequenceNumber) << std::endl;
                std::cout << "Receive packet length " << receivedPacket.dataLength << std::endl;

                memcpy(fileBuffer.data() + offset, receivedPacket.data, receivedPacket.dataLength);


                memcpy(ackBuffer + 3, &ackSeqNet, sizeof(ackSeqNet));
                sendto(socketS, ackBuffer, 7, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                std::cout << "Acknowledged packet: " << sequenceNumber << std::endl;
                writtenPackets.insert(sequenceNumber);

            }
        }
        else {
            std::cerr << "CRC mismatch for packet." << std::endl;
        }
    }

    if (fileBuffer.size() != expectedFileSize) {
        std::cerr << "Error: Buffer size does not match expected file size!" << std::endl;
    }


    if (!outFile.is_open()) {
        std::cerr << "Error: File not open for writing." << std::endl;
        return;
    }

    outFile.write(fileBuffer.data(), fileBuffer.size());
    if (!outFile) {
        std::cerr << "Error: Writing to file failed." << std::endl;
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
