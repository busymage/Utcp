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
	std::this_thread::sleep_for(std::chrono::seconds(1));

	Socket::ErrorCode code;
	Socket socket(&tcp, Socket::SocketType::ACTIVE);
	int ret = socket.connect(0xc0a80250, 8888, code);
	if(ret == 0){
		printf("Connected.\n");
	}else if(ret == -1){
		printf("%s\n", code.msg.c_str());
		return -1;
	}

	std::vector<uint8_t> buffer(1000, 'x');
	for(int i = 0; i < 500; i++)
	{
		socket.send(buffer, code);
		int nrecv = socket.recv(buffer, code);
		printf("recv %d bytes\n", nrecv);
		if(nrecv == 0){
			socket.close();
			break;
		}
	}
	socket.close();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	return 0;
}
