#include <memory>
#include <Protocol/Tcp.hpp>
#include <Protocol/TunNetDevice.hpp>
#include <Protocol/PassiveSock.hpp>
#include <Protocol/ConnectionSock.hpp>
#include <vector>

int main()
{
	std::shared_ptr<INetDevice> netdev = std::make_shared<TunNetDevice>();
	Tcp tcp(netdev);
	tcp.run();
	auto ps = std::make_shared<PassiveSock>(&tcp);
	ps->bind(8888);
	ISock *sock = ps->accept();
	printf("I am here\n");
	while (1)
	{
		std::vector<uint8_t> buffer;
		int nrecv = sock->recv(buffer);
		printf("recv %d bytes\n", nrecv);
	}
	
	return 0;
}
