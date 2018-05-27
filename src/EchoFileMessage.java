
public class EchoFileMessage extends Message {
	
	private String echoFileMessage;

	public EchoFileMessage(String srcUser, String dstUser,String echoFileMessage) {
		super(srcUser, dstUser);
		this.echoFileMessage=echoFileMessage;
	}

	public String getEchoFileMessage() {
		return echoFileMessage;
	}
	
}
