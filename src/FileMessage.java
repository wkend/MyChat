
public class FileMessage extends Message {

	private String fileName;
	private long fileSize;
	private String isAccept;

	public FileMessage(String srcUser, String dstUser, String fileName, String isAccept,long fileSize) {
		super(srcUser, dstUser);
		this.fileName = fileName;
		this.isAccept = isAccept;
		this.fileSize=fileSize;
	}

	public String getFileName() {
		return fileName;
	}
	
	public String getIsAccept() {
		return isAccept;
	}
	
	public long getFileSize() {
		return fileSize;
	}

}
