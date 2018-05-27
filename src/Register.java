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

	// 定义邮箱匹配字符串
	final String strEmail = "[\\w]+@[\\w]+.[\\w]+";
	// 定义手机号码匹配字符串
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

		JButton btnNewButton_login = new JButton("注册");
		btnNewButton_login.addActionListener(new ActionListener() {// 用户注册
			public void actionPerformed(ActionEvent arg0) {

				String userName = textField_UserName.getText();
				String email = textField_email.getText();
				String telphone = textField_telphone.getText();
				String passwd1 = String.valueOf(passwordField_passwd.getPassword());
				String passwd2 = String.valueOf(passwordField_passwd2.getPassword());

				if (btnNewButton_login.getText().equals("注册")) {
					if (userName.length() > 0) {// 验证用户名
						if (email.matches(strEmail)) {// 验证邮箱
							if (telphone.matches(strTelphone)) {// 验证电话号码

								if (passwd1.equals(passwd2)) {
									// 与服务器建立socket连接
									try {
										// 秘钥库密码
										String passphrase = "123456";
										char[] password = passphrase.toCharArray();
										// 秘钥库文件名
										String trustStoreFile = "test.keys";
										// JKS是SUN支持的KeyStore的类型
										KeyStore ts = KeyStore.getInstance("JKS");
										// 打开数字证书
										ts.load(new FileInputStream(trustStoreFile), password);
										// 创建TrustManager对象
										TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
										tmf.init(ts);
										/**
										 * SSLContext类负责设置与安全通信有关的各种信息： 1>使用的协议（SSL/TLS); 2>自身的数字证书以及对方的数字证书；
										 * SSLContext还负责构造SSLServerSocketFactory、SSLSocketFactory和SSLEngine对象
										 */
										// 使用TLS协议
										SSLContext sslContext = SSLContext.getInstance("TLS");
										/**
										 * init(KeyManager[] km, TrustManager[] tm, SecureRandom random)
										 * 参数random:用于设置安全随机数,如果为null，则采用默认的SecureRandom实现;
										 * 参数km:如果为空,会创建一个默认的KeyManager对象，该对象从系统属性javax.net.ssl.keyStore
										 * 中获取数字证书，若不存在这个属性，那么KeyStore对象的内容为空;
										 * 参数tm:如果为空，会创建一个默认的TrustManager对象,以及与之相关的KeyStore对象 KeyStore对象按照以下步骤获取数字证书:
										 * >先尝试从系统属性javax.net.ssl.trustStore中获取数字证书
										 * >若上一步失败,就尝试把<JDK目录>/jre/security/jsscacerts文件作为数字证书文件
										 * >若上一步失败，就尝试把<JDK目录>/jre/security/cacerts文件作为数字证书文件 >若上一步失败，则KeyStore对象内容为空
										 */
										sslContext.init(null, tmf.getTrustManagers(), null);

										/**
										 * SSLSocket类是Socket的子类， SSLSocket类还具有与安全通信有关的方法: 1>设置加密套件 2>处理握手结束事件
										 * 3>管理SSL/TLS会话 4>客户端模式
										 */
										// 创建SSLSocket对象
										SSLSocketFactory factory = sslContext.getSocketFactory();
										registerSocket = (SSLSocket) factory.createSocket("localhost", port);

										// registerSocket = new Socket("localhost", port);
										// 将socket的输入流和输出流分别封装为对象输入流和对象输出流
										oos = new ObjectOutputStream(registerSocket.getOutputStream());
										ois = new ObjectInputStream(registerSocket.getInputStream());
									} catch (UnknownHostException e) {
										JOptionPane.showMessageDialog(Register.this, "服务器主机为找到");
										// TODO Auto-generated catch block
										e.printStackTrace();
										System.exit(0);
									} catch (IOException e) {
										JOptionPane.showMessageDialog(Register.this, "服务器未启动");
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
									// 创建并向服务器发送用户注册消息
									RegisterMessage registerMessage = new RegisterMessage(userName, "", passwd1, email,
											telphone);
									try {
										oos.writeObject(registerMessage);
										oos.flush();
									} catch (IOException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}

									// 接受服务器发来的注册回馈消息
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
										JOptionPane.showMessageDialog(Register.this, "用户" + userName + "注册成功");
										// 隐藏注册窗体
										setVisible(false);
									} else {
										JOptionPane.showMessageDialog(Register.this, "注册失败");
									}
								} else {
									JOptionPane.showMessageDialog(Register.this, "两次输入的密码不一致");
								}

							} else {
								JOptionPane.showMessageDialog(Register.this, "手机号码不规范");
							}
						} else {
							JOptionPane.showMessageDialog(Register.this, "邮箱格式不规范");
						}
					} else {
						JOptionPane.showMessageDialog(Register.this, "用户名不能为空");
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
