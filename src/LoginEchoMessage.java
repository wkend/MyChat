
public class LoginEchoMessage extends Message{
	
	private String loginEchoString;

	public LoginEchoMessage(String srcUser, String dstUser, String loginEchoString) {
		super(srcUser, dstUser);
		this.loginEchoString = loginEchoString;
	}

	public String getLoginEchoString() {
		return loginEchoString;
	}
	
	
}
