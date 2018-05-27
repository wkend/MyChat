

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

		JButton btnNewButton_login = new JButton("��¼");
		btnNewButton_login.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				userName = textField_userName.getText().trim();
				passwd = String.valueOf(passwordField_passwd.getPassword());

				if (btnNewButton_login.getText().equals("��¼")) {
					if (userName.length() > 0) {
						if (passwd.length() > 0) {
							try {
								// �����������socket����
								loginSocket = new Socket("localhost", port);
								oos = new ObjectOutputStream(loginSocket.getOutputStream());
								ois = new ObjectInputStream(loginSocket.getInputStream());
							} catch (UnknownHostException e) {
								JOptionPane.showMessageDialog(Login.this, "����������δ�ҵ�");
								// TODO Auto-generated catch block
								e.printStackTrace();
								System.exit(0);
							} catch (IOException e) {
								JOptionPane.showMessageDialog(Login.this, "������δ����");
								// TODO Auto-generated catch block
								e.printStackTrace();
								System.exit(0);
							}

							// ������������û���¼��Ϣ
							LoginMessage loginMessage = new LoginMessage(userName, "", passwd);
							// ������������û���¼��Ϣ����
							try {
								synchronized (oos) {
									oos.writeObject(loginMessage);
									oos.flush();
								}
								// ���ܷ��������ͻ����ĵ�¼��֤��Ϣ
								String loginEchoMessage = (String) ois.readObject();
								if (loginEchoMessage.equals("ok")) {
									JOptionPane.showMessageDialog(Login.this, "��¼�ɹ�");
									setVisible(false);
									
									//������������û�������Ϣ�����Լ����û������͸�������
									UserStateMessage userStateMessage=new UserStateMessage(userName, "", true);								
									oos.writeObject(userStateMessage);
									oos.flush();
									
									// ��ת���ͻ��˽���
									Client client = new Client();
									client.setVisible(true);
									
								} else if (loginEchoMessage.equals("warning")) {
									JOptionPane.showMessageDialog(Login.this, "��¼ʧ��");
								} else {
									System.out.println("������������");
								}
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (ClassNotFoundException e) {
								JOptionPane.showMessageDialog(Login.this, "���������޷����ܵ�����������֤������Ϣ");
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} else {
							JOptionPane.showMessageDialog(Login.this, "���벻��Ϊ��");
						}

					} else {
						JOptionPane.showMessageDialog(Login.this, "�û�������Ϊ��");
					}
				}
			}
		});
		btnNewButton_login.setBounds(271, 176, 93, 23);
		contentPane.add(btnNewButton_login);

		JButton btnNewButton_register = new JButton("ע��");
		btnNewButton_register.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				// ��ת��ע�����
				Register registerFrame = new Register();
				// setVisible(false);
			}
		});
		btnNewButton_register.setBounds(271, 228, 93, 23);
		contentPane.add(btnNewButton_register);
	}

	// ��ȡ��¼ʱ���û���
	public String getUserName() {
		return userName;
	}

	// ��ȡ��¼ʱ��socket
	public Socket getSocket() {
		return loginSocket;
	}
}
