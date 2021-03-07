#include <memory>
#include <Protocol/Tcp.hpp>
#include <Protocol/TunNetDevice.hpp>

int main()
{
	std::shared_ptr<INetDevice> netdev = std::make_shared<TunNetDevice>();
	Tcp tcp(netdev);
	tcp.addListener(8888);
	tcp.run();	
	return 0;
}
