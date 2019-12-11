#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
	unsigned int ans = (packet[10]<<8) + packet[11];
	unsigned short check_sum = 0;
	unsigned int checksum = 0;

	packet[10] = 0;
	packet[11] = 0;

	int ip_len = (packet[0] << 2) % 64;

	for(int i=0;i<ip_len;i+=2){
		checksum += ((packet[i] << 8) + packet[i+1]);
	}

	while(checksum>>16!=0){
		checksum = (checksum & 0xffff) + (checksum >> 16);
	}

	check_sum = ~checksum;
	if(check_sum==ans)
		return true;
	else
		return false;

}
