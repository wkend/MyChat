
public class OfflineFileMessage extends Message {

	private String offLineMsgContent;
	private long offFileSize;
	
	public OfflineFileMessage(String srcUser, String dstUser, String offLineMsg, long offFileSize) {
		super(srcUser, dstUser);
		this.offLineMsgContent = offLineMsg;
		this.offFileSize=offFileSize;
	}

	public String offLineMsgContent() {
		return offLineMsgContent;
	}

	public long getOffFileSize() {
		return offFileSize;
	}
}
