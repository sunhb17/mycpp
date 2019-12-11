#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */

bool is_mask(uint32_t mask){
  uint32_t test = 0;

  for(int i=0;i<4;i++){
    test += (mask&0xff) << (8 * (3 - i));
    mask = mask >> 8;
  }
  mask = test;
  mask = ~mask;
  while(mask!=0){
    if((mask&0x1)==0x1){
      mask = mask >> 1;
    }
    else return false;
  }
  return true;
}


bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {

  int total_length = packet[3];
  if(total_length>len)
    return false;

  int ip_len = (packet[0] & 0xf);
  int command = 4 * ip_len + 8;
  if(packet[command]!=1&&packet[command]!=2)    
    return false;

  if(packet[command+1]!=2)      
    return false;

  if(packet[command+2]||packet[command+3])
    return false;

  int entry = (total_length - ip_len - 8) / 20;
  output->command = packet[command];
  output->numEntries = entry;

  for(int i=0;i<entry;i++){
    int zero = i * 20 + 4 + command;
    int family = packet[zero+1] + (packet[zero] << 8);

    if((packet[command]==1&&family==0)||(packet[command]==2&&family==2)){
      if((packet[zero+3] + (packet[zero+2]<<8))==0){
        output->entries[i].addr = 0;
        uint32_t mask = 0;
        for(int j=0;j<8;j++){
          if (j<4) output->entries[i].addr += packet[zero+j+4] << (8 * j);
          else mask += packet[zero+j+4] << (8 * (j - 4));
        }
        if(is_mask(mask)){
          output->entries[i].mask = mask;
          output->entries[i].nexthop = 0;
          uint32_t metric = 0;
          for(int j=0;j<8;j++){
            if (j<4) output->entries[i].nexthop += packet[zero+j+12] << (8 * j);
            else metric += packet[zero+j+12] << (8 * (7 - j));
          }
          if(metric>0&&metric<17){
            output->entries[i].metric = 0;
            for(int j=0;j<4;j++){
              output->entries[i].metric += packet[zero+j+16] << (8 * j);
            }
            continue;
          }
        }
      }
    }
    return false;
    
  }
  return true;

}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = 0;
  buffer[3] = 0;

  int numEntries = rip->numEntries;
  int len = numEntries * 20 + 4;

  for(int i=0;i<numEntries;i++){
    int head = i * 20 + 4;

    buffer[head] = 0;
    buffer[head+1] = 2 * rip->command - 2;

    buffer[head+2] = 0;
    buffer[head+3] = 0;

    uint32_t tmp = rip->entries[i].addr;
    for(int j=0;j<4;j++){
      buffer[head+4+j] = tmp & 0xff;
      tmp = tmp >> 8;
    }
    tmp = rip->entries[i].mask;
    for(int j=0;j<4;j++){
      buffer[head+8+j] = tmp & 0xff;
      tmp = tmp >> 8;
    }
    tmp = rip->entries[i].nexthop;
    for(int j=0; j<4;j++){
      buffer[head+12+j] = tmp & 0xff;
      tmp = tmp >> 8;
    }
    tmp = rip->entries[i].metric;
    for(int j=0; j<4; j++){
      buffer[head+16+j] = tmp & 0xff;
      tmp = tmp >> 8;
    }


    
  }
  return len;
}
