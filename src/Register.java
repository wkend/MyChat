import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;

public class Register extends JFrame {

	private JPanel contentPane;
	private JTextField textField_UserName;
	private JPasswordField passwordField_passwd;
	private JTextField textField_telphone;
	private JTextField textField_email;
	private JPasswordField passwordField_passwd2;
	private JLabel lblNewLabel_3;

	private final int port = 9999;
	private Socket registerSocket;
	ObjectInputStream ois;
	ObjectOutputStream oos;

	private String echoMessage;

	// ��������ƥ���ַ���
	final String strEmail = "[\\w]+@[\\w]+.[\\w]+";
	// �����ֻ�����ƥ���ַ���
	final String strTelphone = "^((13[0-9])|(15[^4])|(18[0,2,3,5-9])|(17[0-8])|(147))\\d{8}$";

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Register frame = new Register();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public Register() {
		setTitle("\u6CE8\u518C");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 432);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JLabel lblNewLabel = new JLabel("\u7528\u6237\u540D");
		lblNewLabel.setBounds(40, 46, 79, 15);
		contentPane.add(lblNewLabel);

		JLabel lblNewLabel_1 = new JLabel("\u5BC6\u7801");
		lblNewLabel_1.setBounds(40, 230, 79, 15);
		contentPane.add(lblNewLabel_1);

		textField_UserName = new JTextField();
		textField_UserName.setBounds(129, 43, 215, 21);
		contentPane.add(textField_UserName);
		textField_UserName.setColumns(10);

		passwordField_passwd = new JPasswordField();
		passwordField_passwd.setBounds(129, 227, 215, 21);
		contentPane.add(passwordField_passwd);

		JButton btnNewButton_login = new JButton("ע��");
		btnNewButton_login.addActionListener(new ActionListener() {// �û�ע��
			public void actionPerformed(ActionEvent arg0) {

				String userName = textField_UserName.getText();
				String email = textField_email.getText();
				String telphone = textField_telphone.getText();
				String passwd1 = String.valueOf(passwordField_passwd.getPassword());
				String passwd2 = String.valueOf(passwordField_passwd2.getPassword());

				if (btnNewButton_login.getText().equals("ע��")) {
					if (userName.length() > 0) {// ��֤�û���
						if (email.matches(strEmail)) {// ��֤����
							if (telphone.matches(strTelphone)) {// ��֤�绰����

								if (passwd1.equals(passwd2)) {
									// �����������socket����
									try {
										// ��Կ������
										String passphrase = "123456";
										char[] password = passphrase.toCharArray();
										// ��Կ���ļ���
										String trustStoreFile = "test.keys";
										// JKS��SUN֧�ֵ�KeyStore������
										KeyStore ts = KeyStore.getInstance("JKS");
										// ������֤��
										ts.load(new FileInputStream(trustStoreFile), password);
										// ����TrustManager����
										TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
										tmf.init(ts);
										/**
										 * SSLContext�ฺ�������밲ȫͨ���йصĸ�����Ϣ�� 1>ʹ�õ�Э�飨SSL/TLS); 2>���������֤���Լ��Է�������֤�飻
										 * SSLContext��������SSLServerSocketFactory��SSLSocketFactory��SSLEngine����
										 */
										// ʹ��TLSЭ��
										SSLContext sslContext = SSLContext.getInstance("TLS");
										/**
										 * init(KeyManager[] km, TrustManager[] tm, SecureRandom random)
										 * ����random:�������ð�ȫ�����,���Ϊnull�������Ĭ�ϵ�SecureRandomʵ��;
										 * ����km:���Ϊ��,�ᴴ��һ��Ĭ�ϵ�KeyManager���󣬸ö����ϵͳ����javax.net.ssl.keyStore
										 * �л�ȡ����֤�飬��������������ԣ���ôKeyStore���������Ϊ��;
										 * ����tm:���Ϊ�գ��ᴴ��һ��Ĭ�ϵ�TrustManager����,�Լ���֮��ص�KeyStore���� KeyStore���������²����ȡ����֤��:
										 * >�ȳ��Դ�ϵͳ����javax.net.ssl.trustStore�л�ȡ����֤��
										 * >����һ��ʧ��,�ͳ��԰�<JDKĿ¼>/jre/security/jsscacerts�ļ���Ϊ����֤���ļ�
										 * >����һ��ʧ�ܣ��ͳ��԰�<JDKĿ¼>/jre/security/cacerts�ļ���Ϊ����֤���ļ� >����һ��ʧ�ܣ���KeyStore��������Ϊ��
										 */
										sslContext.init(null, tmf.getTrustManagers(), null);

										/**
										 * SSLSocket����Socket�����࣬ SSLSocket�໹�����밲ȫͨ���йصķ���: 1>���ü����׼� 2>�������ֽ����¼�
										 * 3>����SSL/TLS�Ự 4>�ͻ���ģʽ
										 */
										// ����SSLSocket����
										SSLSocketFactory factory = sslContext.getSocketFactory();
										registerSocket = (SSLSocket) factory.createSocket("localhost", port);

										// registerSocket = new Socket("localhost", port);
										// ��socket����������������ֱ��װΪ�����������Ͷ��������
										oos = new ObjectOutputStream(registerSocket.getOutputStream());
										ois = new ObjectInputStream(registerSocket.getInputStream());
									} catch (UnknownHostException e) {
										JOptionPane.showMessageDialog(Register.this, "����������Ϊ�ҵ�");
										// TODO Auto-generated catch block
										e.printStackTrace();
										System.exit(0);
									} catch (IOException e) {
										JOptionPane.showMessageDialog(Register.this, "������δ����");
										// TODO Auto-generated catch block
										e.printStackTrace();
										System.exit(0);
									} catch (KeyStoreException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									} catch (NoSuchAlgorithmException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									} catch (CertificateException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									} catch (KeyManagementException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}
									// ������������������û�ע����Ϣ
									RegisterMessage registerMessage = new RegisterMessage(userName, "", passwd1, email,
											telphone);
									try {
										oos.writeObject(registerMessage);
										oos.flush();
									} catch (IOException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}

									// ���ܷ�����������ע�������Ϣ
									RegisterEchoMessage registerechoMessage;

									try {
										registerechoMessage = (RegisterEchoMessage) ois.readObject();
										echoMessage = registerechoMessage.getRegisterEchoString();

									} catch (ClassNotFoundException e1) {
										// TODO Auto-generated catch block
										e1.printStackTrace();
									} catch (IOException e1) {
										// TODO Auto-generated catch block
										e1.printStackTrace();
									}

									if (echoMessage.equals("ok")) {
										JOptionPane.showMessageDialog(Register.this, "�û�" + userName + "ע��ɹ�");
										// ����ע�ᴰ��
										setVisible(false);
									} else {
										JOptionPane.showMessageDialog(Register.this, "ע��ʧ��");
									}
								} else {
									JOptionPane.showMessageDialog(Register.this, "������������벻һ��");
								}

							} else {
								JOptionPane.showMessageDialog(Register.this, "�ֻ����벻�淶");
							}
						} else {
							JOptionPane.showMessageDialog(Register.this, "�����ʽ���淶");
						}
					} else {
						JOptionPane.showMessageDialog(Register.this, "�û�������Ϊ��");
					}
				}
			}
		});
		btnNewButton_login.setBounds(331, 360, 93, 23);
		contentPane.add(btnNewButton_login);

		JLabel lblNewLabel_telphone = new JLabel("\u624B\u673A\u53F7\u7801");
		lblNewLabel_telphone.setBounds(40, 168, 79, 15);
		contentPane.add(lblNewLabel_telphone);

		textField_telphone = new JTextField();
		textField_telphone.setBounds(129, 165, 215, 21);
		contentPane.add(textField_telphone);
		textField_telphone.setColumns(10);

		JLabel lblNewLabel_2 = new JLabel("\u90AE\u7BB1");
		lblNewLabel_2.setBounds(40, 107, 79, 15);
		contentPane.add(lblNewLabel_2);

		textField_email = new JTextField();
		textField_email.setBounds(129, 103, 215, 21);
		contentPane.add(textField_email);
		textField_email.setColumns(20);

		passwordField_passwd2 = new JPasswordField();
		passwordField_passwd2.setBounds(129, 289, 215, 21);
		contentPane.add(passwordField_passwd2);

		lblNewLabel_3 = new JLabel("\u786E\u8BA4\u5BC6\u7801");
		lblNewLabel_3.setBounds(40, 292, 54, 15);
		contentPane.add(lblNewLabel_3);

		setVisible(true);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
	}
}
