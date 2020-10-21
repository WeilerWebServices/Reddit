#ifndef _NET_MEMCACHE_CMD_H
#define _NET_MEMCACHE_CMD_H

#include <string>

#include "net/packet.h"
#include "net/pcap.h"

namespace mckeys {

enum memcache_command_t {
  MC_UNKNOWN, MC_REQUEST, MC_RESPONSE
};

class MemcacheCommand
{
 public:
  MemcacheCommand(const Packet &packet,
                  const bpf_u_int32 captureAddress);

  bool isCommand() const
    { return (isRequest() || isResponse()); }
  bool isRequest() const
    { return (cmd_type == MC_REQUEST); }
  bool isResponse() const
    { return (cmd_type == MC_RESPONSE); }

  // only when isRequest is true
  std::string getCommandName() const
    { return commandName; }

  // sometimes when isResponse is true, sometimes when isRequest is true
  std::string getObjectKey() const
    { return objectKey; }

  // only when isResponse is true
  uint32_t getObjectSize() const
    { return objectSize; }

  std::string getSourceAddress() const
    { return sourceAddress; }

 protected:
  void setSourceAddress(const void * src);
  void setCommandName(const std::string &name);

  bool parseResponse(u_char *data, int dataLength);

  memcache_command_t cmd_type;
  std::string sourceAddress;
  std::string commandName;
  std::string objectKey;
  uint32_t objectSize;
};

} // end namespace

#endif
