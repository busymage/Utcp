#include <Protocol/TunNetDevice.hpp>
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

struct TunNetDevice::Impl
{
	int netdev;
};

TunNetDevice::TunNetDevice()
	: impl_(new Impl)
{
	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 * IFF_TAP   - TAP device
	 * IFF_NO_PI - Do not provide packet information
	**/
	impl_->netdev = tun_alloc(IFF_TUN | IFF_NO_PI);
	if (impl_->netdev < 0)
	{
		perror("Allocating interface");
		exit(1);
	}
}
TunNetDevice::~TunNetDevice()
{
	close(impl_->netdev);
}

int TunNetDevice::send(const uint8_t *data, size_t len)
{
	int nwrite = write(impl_->netdev, data, len);
	if (nwrite == -1)
	{
		perror("write to netDevice:");
		exit(1);
	}
}

int TunNetDevice::recv(uint8_t *data, size_t len)
{
	return read(impl_->netdev, data, len);
}
