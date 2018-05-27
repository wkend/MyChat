
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.ProgressMonitorInputStream;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

public class Server extends JFrame {
	private SSLServerSocket serverSocket;
	private final int port = 9999;
	private String offFileUser;// �������ļ��Ľ�����
	private String offFileName;// �����ļ���
	private long offFileSize;// ��ɢ�ļ���С
	private String CurentUser;
	// ���������û����û�����Socket��Ϣ
	private final UserManager userManager = new UserManager();
	// �������û��б�ListModel��,����ά���������û��б�����ʾ������
	final DefaultTableModel onlineUsersDtm = new DefaultTableModel();
	// ���ڿ���ʱ����Ϣ��ʾ��ʽ
	// private final SimpleDateFormat dateFormat = new
	// SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");

	// ������������
	String driver = "org.apache.derby.jdbc.EmbeddedDriver";
	// ���ݿ�����
	String dbName = "USERDB";
	// ����Derby����·��
	String connectionURL = "jdbc:derby:" + dbName + ";create=true";
	Connection connection;

	private final JPanel contentPane;
	private final JTable tableOnlineUsers;
	private final JTextPane textPaneMsgRecord;

	private void errorPrint(Throwable e) {

		if (e instanceof SQLException) {
			SQLExceptionPrint((SQLException) e);
		} else {
			System.out.println("A non SQL error occured.");
			e.printStackTrace();
		}

	}

	private void SQLExceptionPrint(SQLException sqle) {
		while (sqle != null) {
			System.out.println("\n---SQLException Caught---\n");
			System.out.println("SQLState:   " + (sqle).getSQLState());
			System.out.println("Severity: " + (sqle).getErrorCode());
			System.out.println("Message:  " + (sqle).getMessage());
			sqle.printStackTrace();
			sqle = sqle.getNextException();
		}

	}

	private boolean checkTable(Connection connection) throws SQLException {
		try {
			Statement statement = connection.createStatement();
			statement.execute("update USERTABLE set USERNAME= 'TEST', REGISTERTIME = CURRENT_TIMESTAMP where 1=3");
		} catch (SQLException sqle) {
			String err = sqle.getSQLState();
			if (err.equals("42X05")) {// ������
				return false;
			} else if (err.equals("42X14") || err.equals("42821")) {
				System.out
						.println("checkTable: Incorrect table definition. Drop table USERTABLE and rerun this program");
				throw sqle;
			} else {
				System.out.println("checkTable: Unhandled SQLException");
				throw sqle;
			}
		}
		return false;
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					Server frame = new Server();
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
	public Server() {

		// �������ݿ�
		try {
			Class.forName(driver);
			System.out.println(driver + "load...");
		} catch (ClassNotFoundException e) {
			System.err.print("ClassNotFoundException: ");
			System.err.println(e.getMessage());
			System.out.println("\n    >>> Please check your CLASSPATH variable   <<<\n");
		}

		String createString = "create table USERTABLE "// ����
				+ "(USERNAME varchar(20) primary key not null,"// �û���
				+ "HASHEDPWD char(20) for bit data, "// �����hashֵ
				+ "EMAIL varchar(20),"// ����
				+ "telphone varchar(20) ,"// �ֻ�����
				+ "REGISTERTIME timestamp default CURRENT_TIMESTAMP)";// ע��ʱ��

		try {
			connection = DriverManager.getConnection(connectionURL);
			Statement statement = connection.createStatement();
			if (!checkTable(connection)) {
				statement.execute(createString);// �������ݿ�
			}
			statement.close();
			System.out.println("Database openned normally");
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			errorPrint(e);
		}

		setTitle("������");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 561, 403);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);

		JSplitPane splitPaneNorth = new JSplitPane();
		splitPaneNorth.setResizeWeight(0.5);
		contentPane.add(splitPaneNorth, BorderLayout.CENTER);

		JScrollPane scrollPaneMsgRecord = new JScrollPane();
		scrollPaneMsgRecord.setPreferredSize(new Dimension(100, 300));
		scrollPaneMsgRecord.setViewportBorder(
				new TitledBorder(null, "\u6D88\u606F\u8BB0\u5F55", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		splitPaneNorth.setLeftComponent(scrollPaneMsgRecord);

		textPaneMsgRecord = new JTextPane();
		textPaneMsgRecord.setPreferredSize(new Dimension(100, 100));
		scrollPaneMsgRecord.setViewportView(textPaneMsgRecord);

		JScrollPane scrollPaneOnlineUsers = new JScrollPane();
		scrollPaneOnlineUsers.setPreferredSize(new Dimension(100, 300));
		splitPaneNorth.setRightComponent(scrollPaneOnlineUsers);

		onlineUsersDtm.addColumn("�û���");
		onlineUsersDtm.addColumn("IP");
		onlineUsersDtm.addColumn("�˿�");
		onlineUsersDtm.addColumn("��¼ʱ��");
		tableOnlineUsers = new JTable(onlineUsersDtm);
		tableOnlineUsers.setPreferredSize(new Dimension(100, 270));
		tableOnlineUsers.setFillsViewportHeight(true); // ��JTable������������
		scrollPaneOnlineUsers.setViewportView(tableOnlineUsers);

		JPanel panelSouth = new JPanel();
		contentPane.add(panelSouth, BorderLayout.SOUTH);
		panelSouth.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		final JButton btnStart = new JButton("����");
		btnStart.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					SSLContext sslContext = createSSlContext();
					SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

					// ����ServerSocket�򿪶˿�9999�����ͻ�������
					serverSocket = (SSLServerSocket) factory.createServerSocket(port);

					String[] supported = serverSocket.getEnabledCipherSuites();
					serverSocket.setEnabledCipherSuites(supported);

					// �ڡ���Ϣ��¼���ı������ú�ɫ��ʾ�������������ɹ�X��������ʱ����Ϣ
					String msgRecord = dateFormat.format(new Date()) + " �����������ɹ�" + "\r\n";
					addMsgRecord(msgRecord, Color.red, 12, false, false);
					// �����������������û������̡߳������ܲ�����ͻ�����������
					new Thread() {
						@Override
						public void run() {
							while (true) {
								try {
									// ����serverSocket.accept()���������û���������
									Socket socket = serverSocket.accept();
									// Ϊ�������û��������������û������̡߳�
									// ����serverSocket.accept()�������ص�socket���󽻸����û������̡߳�������
									UserHandler userHandler = new UserHandler(socket);
									new Thread(userHandler).start();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
						};
					}.start();
					btnStart.setEnabled(false);
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}

			private SSLContext createSSlContext() throws Exception {
				String keyStoreFile = "test.keys";
				String passphrase = "123456";
				KeyStore ks = KeyStore.getInstance("JKS");
				char[] password = passphrase.toCharArray();
				ks.load(new FileInputStream(keyStoreFile), password);
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(ks, password);

				SSLContext sslContext = SSLContext.getInstance("SSL");
				sslContext.init(kmf.getKeyManagers(), null, null);

				// ��Ҫ��ͻ����ṩ��ȫ֤��ʱ���������˿ɴ���TrustManagerFactory��
				// ����������TrustManager��TrustManger������֮������KeyStore�е���Ϣ��
				// �������Ƿ����ſͻ��ṩ�İ�ȫ֤�顣
				// String trustStoreFile = "client.keys";
				// KeyStore ts = KeyStore.getInstance("JKS");
				// ts.load(new FileInputStream(trustStoreFile), password);
				// TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
				// tmf.init(ts);
				// sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

				return sslContext;
			}
		});
		panelSouth.add(btnStart);
	}

	// ����Ϣ��¼�ı��������һ����Ϣ��¼
	private void addMsgRecord(final String msgRecord, Color msgColor, int fontSize, boolean isItalic,
			boolean isUnderline) {
		final SimpleAttributeSet attrset = new SimpleAttributeSet();
		StyleConstants.setForeground(attrset, msgColor);
		StyleConstants.setFontSize(attrset, fontSize);
		StyleConstants.setUnderline(attrset, isUnderline);
		StyleConstants.setItalic(attrset, isItalic);
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				Document docs = textPaneMsgRecord.getDocument();
				try {
					docs.insertString(docs.getLength(), msgRecord, attrset);
				} catch (BadLocationException e) {
					e.printStackTrace();
				}
			}
		});
	}

	// �û������߳�
	class UserHandler implements Runnable {
		private final Socket currentUserSocket;
		private ObjectInputStream ois;
		private ObjectOutputStream oos;

		public UserHandler(Socket currentUserSocket) {
			this.currentUserSocket = currentUserSocket;
			try {
				ois = new ObjectInputStream(currentUserSocket.getInputStream());
				oos = new ObjectOutputStream(currentUserSocket.getOutputStream());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		@Override
		public void run() {
			Message msg = null;
			try {
				while (true) {
					msg = (Message) ois.readObject();
					if (msg instanceof UserStateMessage) {
						// �����û�״̬��Ϣ
						processUserStateMessage((UserStateMessage) msg);
					} else if (msg instanceof ChatMessage) {
						// ����������Ϣ
						processChatMessage((ChatMessage) msg);
					} else if (msg instanceof RegisterMessage) {
						// �����û�ע����Ϣ
						processRegisterMessage((RegisterMessage) msg);
					} else if (msg instanceof LoginMessage) {
						// �����û���¼��Ϣ
						processLoginMessage((LoginMessage) msg);
					} else if (msg instanceof FileMessage) {
						// �����ļ�����������Ϣ
						processFileMessage((FileMessage) msg);
					} else if (msg instanceof EchoFileMessage) {
						// �����ļ����ͻ�Ӧ��Ϣ
						processEchoFileMessage((EchoFileMessage) msg);
					} else {
						// �����쳣��Ϣ
						processEchoExcepMessage(msg);
					}
				}
			} catch (IOException e) {
				if (e.toString().endsWith("Connection reset")) {
					// ����û�δ����������Ϣ��ֱ�ӹر��˿ͻ��ˣ���ɾ���û�������Ϣ
					if (userManager.removeUser(msg.getSrcUser())) {
						System.out.println("���û���Ϣ�Ѿ��������û��б�ɾ��������");
					}
				} else {
					e.printStackTrace();
				}
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} finally {
				if (currentUserSocket != null) {
					try {
						currentUserSocket.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		// �����쳣��Ϣ
		private void processEchoExcepMessage(Message msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String excepMsgContext = "��Ϣ��ʽ����";

			// ����һ���쳣������Ϣ���ͻ���
			ExceptionEchoMessage excepMsg = new ExceptionEchoMessage(dstUser, dstUser, excepMsgContext);
			try {
				synchronized (oos) {
					oos.writeObject(excepMsg);
					oos.flush();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// ���ļ����ͷ�ת���ļ���Ӧ��Ϣ
		private void processEchoFileMessage(EchoFileMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();

			if (userManager.hasUser(dstUser)) {
				ObjectOutputStream oos = userManager.getUserOos(dstUser);
				try {
					synchronized (oos) {
						oos.writeObject(msg);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
				// ���ͻ��˷���һ���쳣��Ϣ�����߿ͻ���Ŀ���û�������
				String offUserMsg = "Ŀ���û�������";
				ExceptionEchoMessage excepMsg = new ExceptionEchoMessage(dstUser, dstUser, offUserMsg);
				try {
					synchronized (oos) {
						oos.writeObject(msg);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		// �����ļ�����������Ϣ
		private void processFileMessage(FileMessage msg) {

			// �����ļ�����������Ϣ���͸�ָ���ͻ���
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			offFileName = msg.getFileName();
			offFileSize=msg.getFileSize();
			offFileSize = msg.getFileSize();
			offFileUser = dstUser;

			// ��Ŀ���û���ת���ļ�������Ϣ
			if (userManager.hasUser(dstUser)) {
				oos = userManager.getUserOos(dstUser);
				try {
					synchronized (oos) {
						oos.writeObject(msg);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
				// �ļ����ܷ������ߣ�����һ�������ļ����ܻ�����Ϣ���ļ����ͷ���ͬʱ�¿���һ�������˿ڽ��������ļ�
				EchoOffLineFileMessage echoOffLineFileMsg = new EchoOffLineFileMessage("", srcUser, "no user", "8080");
				try {
					synchronized (oos) {
						oos.writeObject(echoOffLineFileMsg);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}


				/* �����µ����������������ļ� */
				// ���������ļ����ܶ˿�8080

				try {
					ServerSocket offFileRevServer = new ServerSocket(8080);
					// ����ļ����ͷ������������ļ����Ϳ�ʼ�����ļ������߳�
					new Thread() {
						@Override
						public void run() {
							while (true) {
								try {// �����ļ����Ͷ˵���������
									Socket fileSocket = offFileRevServer.accept();
									DataInputStream dis = new DataInputStream(fileSocket.getInputStream());
									DataOutputStream dos = new DataOutputStream(
											new FileOutputStream("D:\\��ʱ�ļ�\\" + offFileName));
									byte[] buf = new byte[1024 * 9];
									int len = 0;
									while ((len = dis.read(buf)) != -1) {
										dos.write(buf, 0, len);
									}
									dos.flush();
									if (len == -1) {
										dis.close();
										dos.close();
										JOptionPane.showMessageDialog(Server.this, "�ļ��Ѿ�������D����ʱ�ļ����£�");
									}
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}

							}
						}
					}.start();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		}

		// �����û���¼��Ϣ
		private void processLoginMessage(LoginMessage msg) {
			String srcUser = msg.getSrcUser();
			String passwd = msg.getPasswd();

			try {
				if (!srcUser.isEmpty() && !passwd.isEmpty()) {
					if (userManager.hasUser(srcUser)) {
						// ˵�����û��ظ���¼�������ظ���¼��Ϣ�����û�
						String excepReLogonMsgContent = "���Ѿ���¼�������ٵ�¼��";
						ExceptionEchoMessage excepReLogonMsg = new ExceptionEchoMessage("", srcUser,
								excepReLogonMsgContent);
						try {
							synchronized (oos) {
								oos.writeObject(excepReLogonMsg);
								oos.flush();
							}
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else {
						PreparedStatement checkLoginInfo = connection.prepareStatement(
								"select * from USERTABLE where USERNAME=? and HASHEDPWD=?",
								ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);

						// ������,�����û�����Ψһ�ģ������ｫ�û�����Ϊ��
						// byte[] salt=new byte[16];
						byte[] salt = srcUser.getBytes();
						// SecureRandom sRandom=SecureRandom.getInstance("SHA1PRNG");
						// sRandom.nextBytes(salt);

						// ����ժҪ
						MessageDigest mDigest = MessageDigest.getInstance("SHA-1");
						if (salt != null && salt.length > 0) {
							mDigest.update(salt);
						}
						byte[] hashPasswd = mDigest.digest(passwd.getBytes());
						checkLoginInfo.setString(1, srcUser);
						checkLoginInfo.setBytes(2, hashPasswd);

						ResultSet resultSet = checkLoginInfo.executeQuery();
						resultSet.last();

						int n = resultSet.getRow();
						checkLoginInfo.close();

						String echoString = n > 0 ? "ok" : "warning";

						// �����û���¼������Ϣ
						LoginEchoMessage loginEchoMessage = new LoginEchoMessage(srcUser, "", echoString);
						// ��ͻ��˷��͵�¼��֤���
						try {
							synchronized (oos) {
								oos.writeObject(loginEchoMessage);
								oos.flush();
							}
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}
				}
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		// �����û�ע����Ϣ
		private void processRegisterMessage(RegisterMessage msg) {
			String userName = msg.getSrcUser();
			String userPasswd = msg.getPasswd();
			String userEmail = msg.getEmail();
			String userTelphone = msg.getTelphone();

			// ����ע�������Ϣ�ַ�����Ĭ��Ϊfalse
			String flagString = "warning";

			try {
				// ��ڲ������
				if (!userName.isEmpty() && !userPasswd.isEmpty()) {
					PreparedStatement preStatementTest = connection.prepareStatement(
							"select * from USERTABLE where USERNAME=?", ResultSet.TYPE_SCROLL_INSENSITIVE,
							ResultSet.CONCUR_READ_ONLY);
					preStatementTest.setString(1, userName);
					ResultSet resultSet = preStatementTest.executeQuery();
					resultSet.last();
					int n = resultSet.getRow();
					preStatementTest.close();
					if (n == 0) {

						// �����Σ�
						byte[] salt = userName.getBytes();
						MessageDigest msgDigest = MessageDigest.getInstance("SHA-1");
						if (salt != null && salt.length > 0) {
							msgDigest.update(salt);
						}
						msgDigest.update(userPasswd.getBytes());
						byte[] hashPasswd = msgDigest.digest();
						PreparedStatement preStatementInsert = connection
								.prepareStatement("insert into USERTABLE values (?,?,?,?,?)");
						preStatementInsert.setString(1, userName);
						preStatementInsert.setBytes(2, hashPasswd);// �����hashֵ
						preStatementInsert.setString(3, userEmail);
						preStatementInsert.setString(4, userTelphone);
						preStatementInsert.setTimestamp(5, new Timestamp(System.currentTimeMillis()));
						preStatementInsert.executeUpdate();
						preStatementInsert.close();
						// �޸�ע�������־
						flagString = "ok";
					}
				}
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			// ����ע�������Ϣ
			RegisterEchoMessage registerEchoMesage = new RegisterEchoMessage(userName, "", flagString);
			try {
				synchronized (oos) {
					oos.writeObject(registerEchoMesage);
					oos.flush();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		// �������û�ת��������Ϣ
		private void transferMsgToOtherUsers(Message msg) {
			ObjectOutputStream oos;
			String[] users = userManager.getAllUsers();
			for (String user : users) {
				if (userManager.getUserSocket(user) != currentUserSocket) {
					try {
						oos = userManager.getUserOos(user);
						synchronized (oos) {
							oos.writeObject(msg);
							oos.flush();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		// �����û�״̬��Ϣ
		private void processUserStateMessage(UserStateMessage msg) {
			String srcUser = msg.getSrcUser();
			if (msg.isUserOnline()) { // �û�������Ϣ
				if (userManager.hasUser(srcUser)) {
					// ���������Ӧ���û��ظ���¼��
					return;
				}
				// �������ߵ��û�ת����ǰ�����û��б�
				String[] users = userManager.getAllUsers();
				try {
					for (String user : users) {
						UserStateMessage userStateMessage = new UserStateMessage(user, srcUser, true);
						synchronized (oos) {
							oos.writeObject(userStateMessage);
							oos.flush();
						}
					}
				} catch (IOException e) {
					e.printStackTrace();
				}

				// ���������������û�ת���û�������Ϣ
				transferMsgToOtherUsers(msg);

				/**
				 * ��ȡ���ͻ��˵ĵ�ַ�Ͷ˿ں�
				 */
				// ���û���Ϣ���뵽�������û����б���
				onlineUsersDtm.addRow(new Object[] { srcUser, currentUserSocket.getInetAddress().getHostAddress(),
						currentUserSocket.getPort(), dateFormat.format(new Date()) });

				userManager.addUser(srcUser, currentUserSocket, oos, ois);
				// ����ɫ���ֽ��û������û�����ʱ����ӵ�����Ϣ��¼���ı�����
				String ip = currentUserSocket.getInetAddress().getHostAddress();
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "(" + ip + ")" + "������!\r\n";
				addMsgRecord(msgRecord, Color.green, 12, false, false);

				// �ж��������û��Ƿ��������ļ�Ҫ����
				if (srcUser.equals(offFileUser)) {
					// ���ͻ��˷���һ��˽����Ϣ��ѯ��Ŀ��ͻ��Ƿ���ܸ������ļ�,Ϊ�˷��㣬�ö˿ںŴ�����Ϣ������
					OfflineFileMessage offLineFileMsg = new OfflineFileMessage("9090", offFileUser, offFileName,offFileSize);
					try {
						synchronized (oos) {
							oos.writeObject(offLineFileMsg);
							oos.flush();
						}
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					try {
						// �����µ���������Ŀ���û����������ļ�
						ServerSocket offFileSendServerSocket = new ServerSocket(9090);
						Socket offFileSendSocket = offFileSendServerSocket.accept();

						// ��ʼ�����ļ������߳�
						new Thread() {
							@Override
							public void run() {
								try {
									DataInputStream dis = new DataInputStream(
											new FileInputStream("D:\\��ʱ�ļ�\\" + offFileName));
									DataOutputStream dos = new DataOutputStream(offFileSendSocket.getOutputStream());

									ProgressMonitorInputStream pmi = new ProgressMonitorInputStream(Server.this,
											"������ͻ��˷����ļ�������", dis);

									byte[] buf = new byte[1024 * 9];
									int len = 0;

									while ((len = pmi.read(buf)) != -1) {
										dos.write(buf, 0, len);
									}
									dos.flush();
									if (len == -1) {
										dis.close();
										dos.close();
									}

								} catch (FileNotFoundException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
						}.start();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} else { // �û�������Ϣ
				if (!userManager.hasUser(srcUser)) {
					// ���������Ӧ���û�δ����������Ϣ��ֱ�ӷ�����������Ϣ��Ӧ�÷���Ϣ��ʾ�ͻ��ˣ��������
					System.err.println("�û�δ���͵�¼��Ϣ�ͷ�����������Ϣ");
					return;
				}
				// ����ɫ���ֽ��û������û�����ʱ����ӵ�����Ϣ��¼���ı�����
				String ip = userManager.getUserSocket(srcUser).getInetAddress().getHostAddress();
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "(" + ip + ")" + "������!\r\n";
				addMsgRecord(msgRecord, Color.green, 12, false, false);
				// �ڡ������û��б���ɾ�������û�
				userManager.removeUser(srcUser);
				for (int i = 0; i < onlineUsersDtm.getRowCount(); i++) {
					if (onlineUsersDtm.getValueAt(i, 0).equals(srcUser)) {
						onlineUsersDtm.removeRow(i);
					}
				}
				// ���û�������Ϣת�����������������û�
				transferMsgToOtherUsers(msg);
			}
		}

		// �����û�������������Ϣ
		private void processChatMessage(ChatMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String msgContent = msg.getMsgContent();
			if (userManager.hasUser(srcUser)) {
				// �ú�ɫ���ֽ��յ���Ϣ��ʱ�䡢������Ϣ���û�������Ϣ������ӵ�����Ϣ��¼���ı�����
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + ": \r\n" + msgContent + "\r\n";
				addMsgRecord(msgRecord, Color.black, 12, false, false);
				if (msg.isPubChatMessage()) {
					// ��������Ϣת�����������������û�
					transferMsgToOtherUsers(msg);
				} else {
					// ��˽����Ϣת����Ŀ���û�
					transferMsgToTargetUser(msg);
				}
			} else {
				// ���������Ӧ���û�δ����������Ϣ��ֱ�ӷ�����������Ϣ��Ӧ�÷���Ϣ��ʾ�ͻ��ˣ��������
				System.err.println("����δ����������Ϣ��ֱ�ӷ�����������Ϣ");
				return;
			}
		}

		// ��Ŀ���û�ת��˽����Ϣ
		private void transferMsgToTargetUser(ChatMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String msgContent = msg.getMsgContent();

			if (userManager.hasUser(dstUser)) {
				ObjectOutputStream oos = userManager.getUserOos(dstUser);
				try {
					synchronized (oos) {
						oos.writeObject(msg);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
				String offUserMsgContent = "Ŀ���û������ߣ�";
				ExceptionEchoMessage offUserMsg = new ExceptionEchoMessage("", srcUser, offUserMsgContent);
				try {
					synchronized (oos) {
						oos.writeObject(offUserMsg);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
}

// ���������û���Ϣ
class UserManager {
	private final Map<String, User> onLineUsers;

	public UserManager() {
		onLineUsers = new HashMap<String, User>();
	}

	// �ж�ĳ�û��Ƿ�����
	public boolean hasUser(String userName) {
		return onLineUsers.containsKey(userName);
	}

	// �ж������û��б��Ƿ��
	public boolean isEmpty() {
		return onLineUsers.isEmpty();
	}

	// ��ȡ�����û���Socket�ĵ��������װ�ɵĶ��������
	public ObjectOutputStream getUserOos(String userName) {
		if (hasUser(userName)) {
			return onLineUsers.get(userName).getOos();
		}
		return null;
	}

	// ��ȡ�����û���Socket�ĵ���������װ�ɵĶ���������
	public ObjectInputStream getUserOis(String userName) {
		if (hasUser(userName)) {
			return onLineUsers.get(userName).getOis();
		}
		return null;
	}

	// ��ȡ�����û���Socket
	public Socket getUserSocket(String userName) {
		if (hasUser(userName)) {
			return onLineUsers.get(userName).getSocket();
		}
		return null;
	}

	// ��������û�
	public boolean addUser(String userName, Socket userSocket) {
		if ((userName != null) && (userSocket != null)) {
			onLineUsers.put(userName, new User(userSocket));
			return true;
		}
		return false;
	}

	// ��������û�
	public boolean addUser(String userName, Socket userSocket, ObjectOutputStream oos, ObjectInputStream ios) {
		if ((userName != null) && (userSocket != null) && (oos != null) && (ios != null)) {
			onLineUsers.put(userName, new User(userSocket, oos, ios));
			return true;
		}
		return false;
	}

	// ɾ�������û�
	public boolean removeUser(String userName) {
		if (hasUser(userName)) {
			onLineUsers.remove(userName);
			return true;
		}
		return false;
	}

	// ��ȡ���������û���
	public String[] getAllUsers() {
		String[] users = new String[onLineUsers.size()];
		int i = 0;
		for (Map.Entry<String, User> entry : onLineUsers.entrySet()) {
			users[i++] = entry.getKey();
		}
		return users;
	}

	// ��ȡ�����û�����
	public int getOnlineUserCount() {
		return onLineUsers.size();
	}
}

class User {
	private final Socket socket;
	private ObjectOutputStream oos;
	private ObjectInputStream ois;
	private final Date logonTime;

	public User(Socket socket) {
		this.socket = socket;
		try {
			oos = new ObjectOutputStream(socket.getOutputStream());
			ois = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
		logonTime = new Date();
	}

	public User(Socket socket, ObjectOutputStream oos, ObjectInputStream ois) {
		this.socket = socket;
		this.oos = oos;
		this.ois = ois;
		logonTime = new Date();
	}

	public User(Socket socket, ObjectOutputStream oos, ObjectInputStream ois, Date logonTime) {
		this.socket = socket;
		this.oos = oos;
		this.ois = ois;
		this.logonTime = logonTime;
	}

	public Socket getSocket() {
		return socket;
	}

	public ObjectOutputStream getOos() {
		return oos;
	}

	public ObjectInputStream getOis() {
		return ois;
	}

	public Date getLogonTime() {
		return logonTime;
	}

}
