#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
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

bool forward(uint8_t *packet, size_t len) {
	if(validateIPChecksum(packet,len)==false)
		return false;

	unsigned int checksum = 0;
	unsigned short check_sum = 0;

	packet[8] -= 1;

	int ip_len = (packet[0] << 2) % 64;


	for(int i=0;i<ip_len;i+=2){
		checksum += ((packet[i] << 8) + packet[i+1]);
	}

	while(checksum>>16!=0){
		checksum = (checksum & 0xffff) + (checksum >> 16);
	}

	check_sum = ~checksum;
	packet[11] = (check_sum & 0xff);
	packet[10] = (check_sum & 0xffff) >> 8;
	return true;
}
