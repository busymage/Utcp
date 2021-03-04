#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <vector>

int tun_alloc(int flags)
{

	struct ifreq ifr;
	int fd, err;
	const char *clonedev = "/dev/net/tun";

	if ((fd = open(clonedev, O_RDWR)) < 0)
	{
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
	{
		close(fd);
		return err;
	}

	printf("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

	return fd;
}

int main()
{

	int tun_fd, nread;

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 * IFF_TAP   - TAP device
	 * IFF_NO_PI - Do not provide packet information
	**/
	tun_fd = tun_alloc(IFF_TUN | IFF_NO_PI);

	if (tun_fd < 0)
	{
		perror("Allocating interface");
		exit(1);
	}

	Tcp tcp(tun_fd);

	while (1)
	{
		std::vector<uint8_t> buffer(1500);
		nread = read(tun_fd, buffer.data(), buffer.size());
		if (nread < 0)
		{
			perror("Reading from interface");
			close(tun_fd);
			exit(1);
		}
		printf("got %d bytes\n", nread);
		
		iphdr *inetHdr = (iphdr*)buffer.data();
		if(inetHdr->version != 4){
			continue;
		}
		if(inetHdr->protocol != 0x06){
			continue;
		}
		tcphdr *tcpHdr = (tcphdr*)(buffer.data() + inetHdr->ihl * 4);
		
		SocketPair pair = {
			inetHdr->saddr,
			inetHdr->daddr,
			tcpHdr->source,
			tcpHdr->dest
		};
		
		if(tcp.isEstablished(pair)){
			std::shared_ptr<Tcb> tcb = tcp.getEstablishedConnection(pair);
			tcp.onPacket(tcb, buffer);
		} else if(tcp.hasBoundPort(tcpHdr->dest)){
			tcp.onAccept(buffer);
		} else{
			tcp.onAccept(buffer);
		}
	}

	close(tun_fd);
	return 0;
}
