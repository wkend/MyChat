import java.net.Socket;

public class SocketMessage extends Message {
	
	private Socket socket;

	public SocketMessage(String srcUser, String dstUser,Socket socket) {
		super(srcUser, dstUser);
		this.socket=socket;
	}

	public Socket getSocket() {
		return socket;
	}
	
}
