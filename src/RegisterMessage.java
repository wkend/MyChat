
public class RegisterMessage extends Message{
	
	
	private String passwd;
	private String email;
	private String telphone;

	public RegisterMessage(String srcUser, String dstUser,String passwd,String email,String telphone) {
		super(srcUser, dstUser);
		this.passwd=passwd;
		this.email=email;
		this.telphone=telphone;
	}
	

	public String getPasswd() {
		return passwd;
	}

	public String getEmail() {
		return email;
	}

	public String getTelphone() {
		return telphone;
	}
	
	
	
}
