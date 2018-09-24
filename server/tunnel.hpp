#include "squeue.hpp"

#include <FreeLTE.hpp>
#include <PcapTools.hpp>

#include <map>
#include <boost/thread/shared_mutex.hpp>
#include <memory.h>
#include <pcap.h>

bool establish(uint32_t *, uint8_t *, uint8_t *);
