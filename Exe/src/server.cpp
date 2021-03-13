#include <memory>
#include <Protocol/Tcp.hpp>
#include <Protocol/TunNetDevice.hpp>
#include <Protocol/Socket.hpp>
#include <vector>

int main()
{
	std::shared_ptr<INetDevice> netdev = std::make_shared<TunNetDevice>();
	Tcp tcp(netdev);
	tcp.run();
	
	Socket::ErrorCode code;
	Socket socket(&tcp, Socket::SocketType::PASSIVE);
	socket.bind(8888, code);
	Socket client = socket.accept(code);
	printf("new connection\n");
	while (1)
	{
		std::vector<uint8_t> buffer;
		int nrecv = client.recv(buffer, code);
		printf("recv %d bytes\n", nrecv);
		if(nrecv == 0){
			client.close();
			break;
		}
		client.send(buffer, code);
	}
	
	return 0;
}
