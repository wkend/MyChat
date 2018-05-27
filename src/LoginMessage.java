
public class LoginMessage extends Message{
	
	private String passwd;

	public LoginMessage(String srcUser, String dstUser,String passwd) {
		super(srcUser, dstUser);
		this.passwd=passwd;
	}

	public String getPasswd() {
		return passwd;
	}
}
