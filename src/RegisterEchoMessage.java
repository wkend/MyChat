
public class RegisterEchoMessage extends Message {
	
	private String RegisterEchoString;

	public RegisterEchoMessage(String srcUser, String dstUser, String registerEchoString) {
		super(srcUser, dstUser);
		RegisterEchoString = registerEchoString;
	}

	public String getRegisterEchoString() {
		return RegisterEchoString;
	}
	
}
