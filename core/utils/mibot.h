#ifndef BESS_UTILS_MIBOT_H_
#define BESS_UTILS_MIBOT_H_

#include "endian.h"

namespace bess {
namespace utils {

// A basic UDP header definition.
struct[[gnu::packed]] Mibot {
  be16_t type;    // type = 0:send 1:ack
  be16_t len;    //  packet len  or acked len
};

static_assert(std::is_pod<Mibot>::value, "not a POD type");
static_assert(sizeof(Mibot) == 4, "struct Udp is incorrect");

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_UDP_H_
