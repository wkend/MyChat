public class TestUserDataBase {
	public static void main(String[] args) {
		UserDataBase userDatabase = new UserDataBase();
		// ע���������û�
		userDatabase.insertUser("aaa", "aaa");
		userDatabase.insertUser("bbb", "bbb");
		userDatabase.insertUser("ccc", "ccc");
		// ��ʾ������ע���û���Ϣ
		userDatabase.showAllUsers();
		// �û���"ccc"������"ccc"�Ƿ��ܵ�¼
		if (userDatabase.checkUserPassword("ccc", "ccc") == true) {
			System.out.println("�û�ccc�����ÿ���ccc��¼");
		}
		// ɾ���û�"bbb"
		userDatabase.deleteUser("bbb", "bbb");
		// ��ʾ������ע���û���Ϣ
		userDatabase.showAllUsers();
		userDatabase.shutdownDatabase();
	}
}
