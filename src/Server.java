
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
	private String offFileUser;// 有离线文件的接受者
	private String offFileName;// 离线文件名
	private long offFileSize;// 离散文件大小
	private String CurentUser;
	// 保存在线用户的用户名与Socket信息
	private final UserManager userManager = new UserManager();
	// “在线用户列表ListModel”,用于维护“在线用户列表”中显示的内容
	final DefaultTableModel onlineUsersDtm = new DefaultTableModel();
	// 用于控制时间信息显示格式
	// private final SimpleDateFormat dateFormat = new
	// SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");

	// 定义连接驱动
	String driver = "org.apache.derby.jdbc.EmbeddedDriver";
	// 数据库名称
	String dbName = "USERDB";
	// 定义Derby连接路径
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
			if (err.equals("42X05")) {// 表不存在
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

		// 建立数据库
		try {
			Class.forName(driver);
			System.out.println(driver + "load...");
		} catch (ClassNotFoundException e) {
			System.err.print("ClassNotFoundException: ");
			System.err.println(e.getMessage());
			System.out.println("\n    >>> Please check your CLASSPATH variable   <<<\n");
		}

		String createString = "create table USERTABLE "// 表名
				+ "(USERNAME varchar(20) primary key not null,"// 用户名
				+ "HASHEDPWD char(20) for bit data, "// 口令的hash值
				+ "EMAIL varchar(20),"// 邮箱
				+ "telphone varchar(20) ,"// 手机号码
				+ "REGISTERTIME timestamp default CURRENT_TIMESTAMP)";// 注册时间

		try {
			connection = DriverManager.getConnection(connectionURL);
			Statement statement = connection.createStatement();
			if (!checkTable(connection)) {
				statement.execute(createString);// 创建数据库
			}
			statement.close();
			System.out.println("Database openned normally");
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			errorPrint(e);
		}

		setTitle("服务器");
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

		onlineUsersDtm.addColumn("用户名");
		onlineUsersDtm.addColumn("IP");
		onlineUsersDtm.addColumn("端口");
		onlineUsersDtm.addColumn("登录时间");
		tableOnlineUsers = new JTable(onlineUsersDtm);
		tableOnlineUsers.setPreferredSize(new Dimension(100, 270));
		tableOnlineUsers.setFillsViewportHeight(true); // 让JTable充满它的容器
		scrollPaneOnlineUsers.setViewportView(tableOnlineUsers);

		JPanel panelSouth = new JPanel();
		contentPane.add(panelSouth, BorderLayout.SOUTH);
		panelSouth.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		final JButton btnStart = new JButton("启动");
		btnStart.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					SSLContext sslContext = createSSlContext();
					SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

					// 创建ServerSocket打开端口9999监听客户端连接
					serverSocket = (SSLServerSocket) factory.createServerSocket(port);

					String[] supported = serverSocket.getEnabledCipherSuites();
					serverSocket.setEnabledCipherSuites(supported);

					// 在“消息记录”文本框中用红色显示“服务器启动成功X”和启动时间信息
					String msgRecord = dateFormat.format(new Date()) + " 服务器启动成功" + "\r\n";
					addMsgRecord(msgRecord, Color.red, 12, false, false);
					// 创建并启动“接受用户连接线程”，接受并处理客户端连接请求
					new Thread() {
						@Override
						public void run() {
							while (true) {
								try {
									// 调用serverSocket.accept()方法接受用户连接请求
									Socket socket = serverSocket.accept();
									// 为新来的用户创建并启动“用户服务线程”
									// 并把serverSocket.accept()方法返回的socket对象交给“用户服务线程”来处理
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

				// 当要求客户端提供安全证书时，服务器端可创建TrustManagerFactory，
				// 并由它创建TrustManager，TrustManger根据与之关联的KeyStore中的信息，
				// 来决定是否相信客户提供的安全证书。
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

	// 向消息记录文本框中添加一条消息记录
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

	// 用户服务线程
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
						// 处理用户状态消息
						processUserStateMessage((UserStateMessage) msg);
					} else if (msg instanceof ChatMessage) {
						// 处理聊天消息
						processChatMessage((ChatMessage) msg);
					} else if (msg instanceof RegisterMessage) {
						// 处理用户注册消息
						processRegisterMessage((RegisterMessage) msg);
					} else if (msg instanceof LoginMessage) {
						// 处理用户登录消息
						processLoginMessage((LoginMessage) msg);
					} else if (msg instanceof FileMessage) {
						// 处理文件发送请求消息
						processFileMessage((FileMessage) msg);
					} else if (msg instanceof EchoFileMessage) {
						// 处理文件发送回应消息
						processEchoFileMessage((EchoFileMessage) msg);
					} else {
						// 处理异常消息
						processEchoExcepMessage(msg);
					}
				}
			} catch (IOException e) {
				if (e.toString().endsWith("Connection reset")) {
					// 如果用户未发送下线消息就直接关闭了客户端，，删除用户在线信息
					if (userManager.removeUser(msg.getSrcUser())) {
						System.out.println("该用户信息已经从在线用户列表删除，，，");
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

		// 处理异常消息
		private void processEchoExcepMessage(Message msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String excepMsgContext = "消息格式错误！";

			// 创建一条异常回馈消息给客户端
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

		// 给文件发送方转发文件回应消息
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
				// 给客户端发送一条异常消息，告诉客户端目标用户不在线
				String offUserMsg = "目标用户不在线";
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

		// 处理文件发送请求消息
		private void processFileMessage(FileMessage msg) {

			// 将该文件发送请求消息发送给指定客户端
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			offFileName = msg.getFileName();
			offFileSize=msg.getFileSize();
			offFileSize = msg.getFileSize();
			offFileUser = dstUser;

			// 给目标用户端转发文件请求消息
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
				// 文件接受方不在线，创建一个离线文件接受回馈消息给文件发送方，同时新开启一个监听端口接受离线文件
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


				/* 创建新的连接来接受离线文件 */
				// 监听离线文件接受端口8080

				try {
					ServerSocket offFileRevServer = new ServerSocket(8080);
					// 如果文件发送方发送了离线文件，就开始离线文件接受线程
					new Thread() {
						@Override
						public void run() {
							while (true) {
								try {// 接受文件发送端的连接请求
									Socket fileSocket = offFileRevServer.accept();
									DataInputStream dis = new DataInputStream(fileSocket.getInputStream());
									DataOutputStream dos = new DataOutputStream(
											new FileOutputStream("D:\\临时文件\\" + offFileName));
									byte[] buf = new byte[1024 * 9];
									int len = 0;
									while ((len = dis.read(buf)) != -1) {
										dos.write(buf, 0, len);
									}
									dos.flush();
									if (len == -1) {
										dis.close();
										dos.close();
										JOptionPane.showMessageDialog(Server.this, "文件已经保存在D盘临时文件夹下！");
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

		// 处理用户登录消息
		private void processLoginMessage(LoginMessage msg) {
			String srcUser = msg.getSrcUser();
			String passwd = msg.getPasswd();

			try {
				if (!srcUser.isEmpty() && !passwd.isEmpty()) {
					if (userManager.hasUser(srcUser)) {
						// 说明该用户重复登录，发送重复登录消息给该用户
						String excepReLogonMsgContent = "您已经登录，无需再登录！";
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

						// 生成盐,由于用户名是唯一的，在这里将用户名作为盐
						// byte[] salt=new byte[16];
						byte[] salt = srcUser.getBytes();
						// SecureRandom sRandom=SecureRandom.getInstance("SHA1PRNG");
						// sRandom.nextBytes(salt);

						// 生成摘要
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

						// 创建用户登录回馈消息
						LoginEchoMessage loginEchoMessage = new LoginEchoMessage(srcUser, "", echoString);
						// 向客户端发送登录验证结果
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

		// 处理用户注册消息
		private void processRegisterMessage(RegisterMessage msg) {
			String userName = msg.getSrcUser();
			String userPasswd = msg.getPasswd();
			String userEmail = msg.getEmail();
			String userTelphone = msg.getTelphone();

			// 定义注册回馈消息字符串，默认为false
			String flagString = "warning";

			try {
				// 入口参数检查
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

						// 生成盐，
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
						preStatementInsert.setBytes(2, hashPasswd);// 口令的hash值
						preStatementInsert.setString(3, userEmail);
						preStatementInsert.setString(4, userTelphone);
						preStatementInsert.setTimestamp(5, new Timestamp(System.currentTimeMillis()));
						preStatementInsert.executeUpdate();
						preStatementInsert.close();
						// 修改注册回馈标志
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

			// 创建注册回馈消息
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

		// 向其它用户转发公聊消息
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

		// 处理用户状态消息
		private void processUserStateMessage(UserStateMessage msg) {
			String srcUser = msg.getSrcUser();
			if (msg.isUserOnline()) { // 用户上线消息
				if (userManager.hasUser(srcUser)) {
					// 这种情况对应着用户重复登录，
					return;
				}
				// 向新上线的用户转发当前在线用户列表
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

				// 向所有其它在线用户转发用户上线消息
				transferMsgToOtherUsers(msg);

				/**
				 * 获取到客户端的地址和端口号
				 */
				// 将用户信息加入到“在线用户”列表中
				onlineUsersDtm.addRow(new Object[] { srcUser, currentUserSocket.getInetAddress().getHostAddress(),
						currentUserSocket.getPort(), dateFormat.format(new Date()) });

				userManager.addUser(srcUser, currentUserSocket, oos, ois);
				// 用绿色文字将用户名和用户上线时间添加到“消息记录”文本框中
				String ip = currentUserSocket.getInetAddress().getHostAddress();
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "(" + ip + ")" + "上线了!\r\n";
				addMsgRecord(msgRecord, Color.green, 12, false, false);

				// 判断新上线用户是否有离线文件要接受
				if (srcUser.equals(offFileUser)) {
					// 给客户端发送一条私聊消息，询问目标客户是否接受该离线文件,为了方便，用端口号代替消息发送者
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
						// 创建新的连接来给目标用户发送离线文件
						ServerSocket offFileSendServerSocket = new ServerSocket(9090);
						Socket offFileSendSocket = offFileSendServerSocket.accept();

						// 开始离线文件发送线程
						new Thread() {
							@Override
							public void run() {
								try {
									DataInputStream dis = new DataInputStream(
											new FileInputStream("D:\\临时文件\\" + offFileName));
									DataOutputStream dos = new DataOutputStream(offFileSendSocket.getOutputStream());

									ProgressMonitorInputStream pmi = new ProgressMonitorInputStream(Server.this,
											"正在向客户端发送文件，，，", dis);

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
			} else { // 用户下线消息
				if (!userManager.hasUser(srcUser)) {
					// 这种情况对应着用户未发送上线消息就直接发送了下线消息，应该发消息提示客户端，这里从略
					System.err.println("用户未发送登录消息就发送了下线消息");
					return;
				}
				// 用绿色文字将用户名和用户下线时间添加到“消息记录”文本框中
				String ip = userManager.getUserSocket(srcUser).getInetAddress().getHostAddress();
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "(" + ip + ")" + "下线了!\r\n";
				addMsgRecord(msgRecord, Color.green, 12, false, false);
				// 在“在线用户列表”中删除下线用户
				userManager.removeUser(srcUser);
				for (int i = 0; i < onlineUsersDtm.getRowCount(); i++) {
					if (onlineUsersDtm.getValueAt(i, 0).equals(srcUser)) {
						onlineUsersDtm.removeRow(i);
					}
				}
				// 将用户下线消息转发给所有其它在线用户
				transferMsgToOtherUsers(msg);
			}
		}

		// 处理用户发来的聊天消息
		private void processChatMessage(ChatMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String msgContent = msg.getMsgContent();
			if (userManager.hasUser(srcUser)) {
				// 用黑色文字将收到消息的时间、发送消息的用户名和消息内容添加到“消息记录”文本框中
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + ": \r\n" + msgContent + "\r\n";
				addMsgRecord(msgRecord, Color.black, 12, false, false);
				if (msg.isPubChatMessage()) {
					// 将公聊消息转发给所有其它在线用户
					transferMsgToOtherUsers(msg);
				} else {
					// 将私聊消息转发给目标用户
					transferMsgToTargetUser(msg);
				}
			} else {
				// 这种情况对应着用户未发送上线消息就直接发送了聊天消息，应该发消息提示客户端，这里从略
				System.err.println("用启未发送上线消息就直接发送了聊天消息");
				return;
			}
		}

		// 向目标用户转发私聊消息
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
				String offUserMsgContent = "目标用户不在线！";
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

// 管理在线用户信息
class UserManager {
	private final Map<String, User> onLineUsers;

	public UserManager() {
		onLineUsers = new HashMap<String, User>();
	}

	// 判断某用户是否在线
	public boolean hasUser(String userName) {
		return onLineUsers.containsKey(userName);
	}

	// 判断在线用户列表是否空
	public boolean isEmpty() {
		return onLineUsers.isEmpty();
	}

	// 获取在线用户的Socket的的输出流封装成的对象输出流
	public ObjectOutputStream getUserOos(String userName) {
		if (hasUser(userName)) {
			return onLineUsers.get(userName).getOos();
		}
		return null;
	}

	// 获取在线用户的Socket的的输入流封装成的对象输入流
	public ObjectInputStream getUserOis(String userName) {
		if (hasUser(userName)) {
			return onLineUsers.get(userName).getOis();
		}
		return null;
	}

	// 获取在线用户的Socket
	public Socket getUserSocket(String userName) {
		if (hasUser(userName)) {
			return onLineUsers.get(userName).getSocket();
		}
		return null;
	}

	// 添加在线用户
	public boolean addUser(String userName, Socket userSocket) {
		if ((userName != null) && (userSocket != null)) {
			onLineUsers.put(userName, new User(userSocket));
			return true;
		}
		return false;
	}

	// 添加在线用户
	public boolean addUser(String userName, Socket userSocket, ObjectOutputStream oos, ObjectInputStream ios) {
		if ((userName != null) && (userSocket != null) && (oos != null) && (ios != null)) {
			onLineUsers.put(userName, new User(userSocket, oos, ios));
			return true;
		}
		return false;
	}

	// 删除在线用户
	public boolean removeUser(String userName) {
		if (hasUser(userName)) {
			onLineUsers.remove(userName);
			return true;
		}
		return false;
	}

	// 获取所有在线用户名
	public String[] getAllUsers() {
		String[] users = new String[onLineUsers.size()];
		int i = 0;
		for (Map.Entry<String, User> entry : onLineUsers.entrySet()) {
			users[i++] = entry.getKey();
		}
		return users;
	}

	// 获取在线用户个数
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
