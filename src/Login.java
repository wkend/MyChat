

import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.awt.event.ActionEvent;

public class Login extends JFrame {

	private JPanel contentPane;
	private JTextField textField_userName;
	private JPasswordField passwordField_passwd;

	private String userName;
	private String passwd;
	private Socket loginSocket;
	private final int port = 9999;
	private ObjectInputStream ois;
	private ObjectOutputStream oos;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Login frame = new Login();
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
	public Login() {
		setTitle("MyChat");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JLabel lblNewLabel_userName = new JLabel("\u7528\u6237\u540D");
		lblNewLabel_userName.setBounds(82, 50, 54, 15);
		contentPane.add(lblNewLabel_userName);

		JLabel lblNewLabel_passwd = new JLabel("\u5BC6\u7801");
		lblNewLabel_passwd.setBounds(82, 112, 54, 15);
		contentPane.add(lblNewLabel_passwd);

		textField_userName = new JTextField();
		textField_userName.setBounds(167, 47, 197, 21);
		contentPane.add(textField_userName);
		textField_userName.setColumns(10);

		passwordField_passwd = new JPasswordField();
		passwordField_passwd.setBounds(167, 109, 197, 21);
		contentPane.add(passwordField_passwd);

		JButton btnNewButton_login = new JButton("登录");
		btnNewButton_login.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				userName = textField_userName.getText().trim();
				passwd = String.valueOf(passwordField_passwd.getPassword());

				if (btnNewButton_login.getText().equals("登录")) {
					if (userName.length() > 0) {
						if (passwd.length() > 0) {
							try {
								// 与服务器建立socket连接
								loginSocket = new Socket("localhost", port);
								oos = new ObjectOutputStream(loginSocket.getOutputStream());
								ois = new ObjectInputStream(loginSocket.getInputStream());
							} catch (UnknownHostException e) {
								JOptionPane.showMessageDialog(Login.this, "服务器主机未找到");
								// TODO Auto-generated catch block
								e.printStackTrace();
								System.exit(0);
							} catch (IOException e) {
								JOptionPane.showMessageDialog(Login.this, "服务器未启动");
								// TODO Auto-generated catch block
								e.printStackTrace();
								System.exit(0);
							}

							// 向服务器发送用户登录消息
							LoginMessage loginMessage = new LoginMessage(userName, "", passwd);
							// 向服务器发送用户登录消息对象
							try {
								synchronized (oos) {
									oos.writeObject(loginMessage);
									oos.flush();
								}
								// 接受服务器发送回来的登录验证消息
								String loginEchoMessage = (String) ois.readObject();
								if (loginEchoMessage.equals("ok")) {
									JOptionPane.showMessageDialog(Login.this, "登录成功");
									setVisible(false);
									
									//向服务器发送用户上线消息，将自己的用户名发送给服务器
									UserStateMessage userStateMessage=new UserStateMessage(userName, "", true);								
									oos.writeObject(userStateMessage);
									oos.flush();
									
									// 跳转到客户端界面
									Client client = new Client();
									client.setVisible(true);
									
								} else if (loginEchoMessage.equals("warning")) {
									JOptionPane.showMessageDialog(Login.this, "登录失败");
								} else {
									System.out.println("见鬼啦，，，");
								}
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (ClassNotFoundException e) {
								JOptionPane.showMessageDialog(Login.this, "发生错误，无法接受到服务器的验证回馈消息");
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} else {
							JOptionPane.showMessageDialog(Login.this, "密码不能为空");
						}

					} else {
						JOptionPane.showMessageDialog(Login.this, "用户名不能为空");
					}
				}
			}
		});
		btnNewButton_login.setBounds(271, 176, 93, 23);
		contentPane.add(btnNewButton_login);

		JButton btnNewButton_register = new JButton("注册");
		btnNewButton_register.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				// 跳转到注册界面
				Register registerFrame = new Register();
				// setVisible(false);
			}
		});
		btnNewButton_register.setBounds(271, 228, 93, 23);
		contentPane.add(btnNewButton_register);
	}

	// 获取登录时的用户名
	public String getUserName() {
		return userName;
	}

	// 获取登录时的socket
	public Socket getSocket() {
		return loginSocket;
	}
}
