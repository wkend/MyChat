
public class P2PMesage extends Message {

	private String p2pMessageContent;

	public P2PMesage(String srcUser, String dstUser, String p2pMessage) {
		super(srcUser, dstUser);
		this.p2pMessageContent = p2pMessage;
	}

	public String getP2pMessageContent() {
		return p2pMessageContent;
	}

}
