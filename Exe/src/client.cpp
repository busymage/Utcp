#include <memory>
#include <Protocol/Tcp.hpp>
#include <Protocol/TunNetDevice.hpp>
#include <Protocol/ConnectionSock.hpp>
#include <vector>

int main()
{
	std::shared_ptr<INetDevice> netdev = std::make_shared<TunNetDevice>();
	Tcp tcp(netdev);
	tcp.run();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	auto conn = std::make_shared<ConnectionSock>(&tcp);
	int ret = conn->connect(0xc0a80250, 8888);
	if(ret == 0){
		printf("Connected.\n");
	}else if(ret == -2){
		printf("Connection reset by peer.\n");
		return ret;
	} else if(ret == -4){
		printf("Connection timeout.\n");
		return ret;
	}

	std::vector<uint8_t> buffer(1000, 'x');
	for(int i = 0; i < 500; i++)
	{
		conn->send(buffer);
		int nrecv = conn->recv(buffer);
		printf("recv %d bytes\n", nrecv);
		if(nrecv == 0){
			conn->close();
			break;
		}
	}
	conn->close();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	return 0;
}
