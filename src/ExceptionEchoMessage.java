
public class ExceptionEchoMessage extends Message {

	private String exceptionEchoMessage;

	public ExceptionEchoMessage(String srcUser, String dstUser, String exceptionEchoMessage) {
		super(srcUser, dstUser);
		this.exceptionEchoMessage = exceptionEchoMessage;
	}

	public String getExceptionEchoMessage() {
		return exceptionEchoMessage;
	}
	
}
