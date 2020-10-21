#include <iostream>
#include <iomanip>
#include <string>

#include "net/net.h"

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

// from memcached's protocol_binary.h
typedef union {
  struct {
    uint8_t magic;
    uint8_t opcode;
    uint16_t keylen;
    uint8_t extlen;
    uint8_t datatype;
    uint16_t status;
    uint32_t bodylen;
    uint32_t opaque;
    uint64_t cas;
  } response;
  uint8_t bytes[24];
} protocol_binary_response_header;

typedef enum {
  PROTOCOL_BINARY_CMD_GETK = 0x0c,
  PROTOCOL_BINARY_CMD_GETKQ = 0x0d
} protocol_binary_command;

}

namespace mckeys {

using namespace std;

// constructor
MemcacheCommand::MemcacheCommand(const Packet& _packet,
                                 const bpf_u_int32 captureAddress)
    : cmd_type(MC_UNKNOWN), sourceAddress(),
      commandName(), objectKey(), objectSize(0)
{
  static ssize_t ether_header_sz = sizeof(struct ether_header);
  static ssize_t ip_sz = sizeof(struct ip);

  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;

  const Packet::Header* pkthdr = &_packet.getHeader();
  const Packet::Data* packet = _packet.getData();

  bool possible_request = false;
  u_char *data;
  uint32_t dataLength = 0;
  uint32_t dataOffset;

  // must be an IP packet
  ethernetHeader = (struct ether_header*)packet;
  if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP) {
    return;
  }

  // must be TCP - TODO add support for UDP
  ipHeader = (struct ip*)(packet + ether_header_sz);
  if (ipHeader->ip_p != IPPROTO_TCP) {
    return;
  }
  setSourceAddress(&(ipHeader->ip_src));

  // The packet was destined for our capture address, this is a request
  // This bit of optimization lets us ignore a reasonably large percentage of
  // traffic
  if (ipHeader->ip_dst.s_addr == captureAddress) {
    possible_request = true;
  }

  tcpHeader = (struct tcphdr*)(packet + ether_header_sz + ip_sz);
  dataOffset = ether_header_sz + ip_sz + (tcpHeader->doff * 4);
  data = (u_char*)(packet + dataOffset);
  dataLength = pkthdr->len - dataOffset;
  if (dataLength > pkthdr->caplen) {
    dataLength = pkthdr->caplen;
  }

  if (!possible_request && parseResponse(data, dataLength)) {
    cmd_type = MC_RESPONSE;
  }
}

// protected
bool MemcacheCommand::parseResponse(u_char *data, int length)
{
  static ssize_t hdr_size = sizeof(protocol_binary_response_header);

  const protocol_binary_response_header* header;
  uint32_t keyLength;
  uint32_t extrasLength;

  // we must at least have a full header
  if (length < hdr_size) {
    return false;
  }

  header = reinterpret_cast<const protocol_binary_response_header*>(data);

  if (header->response.magic != 0x81) {
    return false;
  }

  if (header->response.opcode != PROTOCOL_BINARY_CMD_GETK &&
      header->response.opcode != PROTOCOL_BINARY_CMD_GETKQ) {
    return false;
  }

  keyLength = ntohs(header->response.keylen);
  extrasLength = header->response.extlen;

  if (length < hdr_size + extrasLength + keyLength) {
    return false;
  }

  this->objectSize = ntohl(header->response.bodylen) - keyLength - extrasLength;
  this->objectKey = std::string(reinterpret_cast<const char*>(data + hdr_size + extrasLength), keyLength);

  return true;
}

void MemcacheCommand::setSourceAddress(const void * src)
{
  char sourceIp[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, src, sourceIp, INET_ADDRSTRLEN);
  sourceAddress = sourceIp;
}
void MemcacheCommand::setCommandName(const std::string &name)
{
  commandName = name;
}

} // end namespace
