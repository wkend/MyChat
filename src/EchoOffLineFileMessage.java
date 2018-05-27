
public class EchoOffLineFileMessage extends Message {

	private String echoOffLineFileMsgContent;
	private String offLinePort;

	public EchoOffLineFileMessage(String srcUser, String dstUser, String echoOffLineFileMsg, String offLinePort) {
		super(srcUser, dstUser);
		this.echoOffLineFileMsgContent = echoOffLineFileMsg;
		this.offLinePort = offLinePort;

	}

	public String getEchoOffLineFileMsgContent() {
		return echoOffLineFileMsgContent;
	}

	public String getOffLinePort() {
		return offLinePort;
	}

}
