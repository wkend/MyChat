
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.HeadlessException;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.ProgressMonitorInputStream;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.JRadioButton;

public class Client extends JFrame {
	private final int port = 9999;
	private int fileSocketPort;
	private SSLSocket socket;
	ObjectInputStream ois;
	ObjectOutputStream oos;
	private String localUserName;
	private String passwd;
	private String msgMessage;// 待发送的消息内容

	private String targetUser;// 私聊对象
	private String fileName;// 待发送的文件名
	private String filePath;// 待发送的文件路径
	private long fileSize;// 待发送的文件大小

	// “在线用户列表ListModel”,用于维护“在线用户列表”中显示的内容
	private final DefaultListModel<String> onlineUserDlm = new DefaultListModel<String>();
	// 用于控制时间信息显示格式
	// private final SimpleDateFormat dateFormat = new
	// SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");

	private JProgressBar jProgressBar;
	private final JPanel contentPane;
	private final JTextField textFieldUserName;
	private final JPasswordField passwordFieldPwd;
	private final JTextField textFieldMsgToSend;
	private final JTextPane textPaneMsgRecord;
	private final JList<String> listOnlineUsers;
	private final JButton btnLogin;
	private final JButton btnSendMsg;
	private final JButton btnSendFile;
	private JRadioButton rdbtnNewRadioButton_pubChat;
	private JRadioButton rdbtnNewRadioButton_priChat;
	private final JButton btnNewButton_register;
	private JLabel lblPwd;
	//private JProgressBar progressBar;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					Client frame = new Client();
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
	public Client() {

		jProgressBar = new JProgressBar();
		setTitle(localUserName);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 579, 362);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);

		JPanel panelNorth = new JPanel();
		panelNorth.setBorder(new EmptyBorder(0, 0, 5, 0));
		contentPane.add(panelNorth, BorderLayout.NORTH);
		panelNorth.setLayout(new BoxLayout(panelNorth, BoxLayout.X_AXIS));

		JLabel lblUserName = new JLabel("\u7528\u6237\u540D\uFF1A");
		panelNorth.add(lblUserName);

		textFieldUserName = new JTextField();
		panelNorth.add(textFieldUserName);
		textFieldUserName.setColumns(5);

		Component horizontalStrut = Box.createHorizontalStrut(20);
		panelNorth.add(horizontalStrut);

		lblPwd = new JLabel("\u5BC6\u7801\uFF1A");
		panelNorth.add(lblPwd);

		passwordFieldPwd = new JPasswordField();
		passwordFieldPwd.setColumns(10);
		panelNorth.add(passwordFieldPwd);

		Component horizontalStrut_1 = Box.createHorizontalStrut(20);
		panelNorth.add(horizontalStrut_1);

		btnLogin = new JButton("登录");
		btnLogin.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (btnLogin.getText().equals("登录")) {
					localUserName = textFieldUserName.getText().trim();
					passwd = String.valueOf(passwordFieldPwd.getPassword());

					if (btnLogin.getText().equals("登录")) {
						if (localUserName.length() > 0) {
							if (passwd.length() > 0) {
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

									SSLContext sslContext = SSLContext.getInstance("TLS");
									sslContext.init(null, tmf.getTrustManagers(), null);
									// 创建SSLSocket对象
									SSLSocketFactory factory = sslContext.getSocketFactory();
									// 与服务器建立socket连接
									socket = (SSLSocket) factory.createSocket("localhost", port);

									oos = new ObjectOutputStream(socket.getOutputStream());
									ois = new ObjectInputStream(socket.getInputStream());
								} catch (UnknownHostException e1) {
									JOptionPane.showMessageDialog(Client.this, "服务器主机未找到");
									// TODO Auto-generated catch block
									e1.printStackTrace();
									System.exit(0);
								} catch (IOException e1) {
									JOptionPane.showMessageDialog(Client.this, "服务器未启动");
									// TODO Auto-generated catch block
									e1.printStackTrace();
									System.exit(0);
								} catch (KeyStoreException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (NoSuchAlgorithmException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (CertificateException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (KeyManagementException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}

								// 创建并启动后台监听线程
								new Thread(new ListeningHandler()).start();
								// 向服务器发送用户登录请求消息
								LoginMessage loginMessage = new LoginMessage(localUserName, "", passwd);
								// 向服务器发送用户登录请求消息对象
								try {
									synchronized (oos) {
										oos.writeObject(loginMessage);
										oos.flush();
									}

								} catch (IOException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}
							} else {
								JOptionPane.showMessageDialog(Client.this, "密码不能为空");
							}
						} else {
							JOptionPane.showMessageDialog(Client.this, "用户名不能为空");
						}
					}
				} else if (btnLogin.getText().equals("退出")) {
					if (JOptionPane.showConfirmDialog(Client.this, "是否退出?", "退出确认",
							JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION) {
						// 向服务器发送用户下线消息
						UserStateMessage userStateMessage = new UserStateMessage(localUserName, "", false);
						try {
							synchronized (oos) {
								oos.writeObject(userStateMessage);
								oos.flush();
							}
							System.exit(0);
						} catch (IOException e1) {
							e1.printStackTrace();
						} finally {
							if (oos != null) {
								try {
									oos.close();
									socket.close();
								} catch (IOException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}
							}
						}
					}
				}
			}
		});
		panelNorth.add(btnLogin);
		Component horizontalStrut_4 = Box.createHorizontalStrut(20);
		panelNorth.add(horizontalStrut_4);

		btnNewButton_register = new JButton("注册");
		btnNewButton_register.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Register register = new Register();
				register.setVisible(true);
				btnNewButton_register.setEnabled(false);
			}
		});
		panelNorth.add(btnNewButton_register);

		JSplitPane splitPaneCenter = new JSplitPane();
		splitPaneCenter.setResizeWeight(1.0);
		contentPane.add(splitPaneCenter, BorderLayout.CENTER);

		JScrollPane scrollPaneMsgRecord = new JScrollPane();
		scrollPaneMsgRecord.setViewportBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"),
				"\u6D88\u606F\u8BB0\u5F55", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		splitPaneCenter.setLeftComponent(scrollPaneMsgRecord);

		textPaneMsgRecord = new JTextPane();
		scrollPaneMsgRecord.setViewportView(textPaneMsgRecord);
		
		
		jProgressBar = new JProgressBar();
		jProgressBar.setStringPainted(true);
		jProgressBar.setForeground(Color.GREEN);
		scrollPaneMsgRecord.setColumnHeaderView(jProgressBar);

		JScrollPane scrollPaneOnlineUsers = new JScrollPane();
		scrollPaneOnlineUsers.setViewportBorder(
				new TitledBorder(null, "\u5728\u7EBF\u7528\u6237", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		splitPaneCenter.setRightComponent(scrollPaneOnlineUsers);

		listOnlineUsers = new JList<String>(onlineUserDlm);
		scrollPaneOnlineUsers.setViewportView(listOnlineUsers);

		JPanel panelSouth = new JPanel();
		panelSouth.setBorder(new EmptyBorder(5, 0, 0, 0));
		contentPane.add(panelSouth, BorderLayout.SOUTH);
		panelSouth.setLayout(new BoxLayout(panelSouth, BoxLayout.X_AXIS));

		rdbtnNewRadioButton_pubChat = new JRadioButton("\u516C\u804A");
		panelSouth.add(rdbtnNewRadioButton_pubChat);

		Component horizontalStrut_5 = Box.createHorizontalStrut(20);
		panelSouth.add(horizontalStrut_5);

		rdbtnNewRadioButton_priChat = new JRadioButton("\u79C1\u804A");
		panelSouth.add(rdbtnNewRadioButton_priChat);

		Component horizontalStrut_6 = Box.createHorizontalStrut(20);
		panelSouth.add(horizontalStrut_6);

		textFieldMsgToSend = new JTextField();
		panelSouth.add(textFieldMsgToSend);
		textFieldMsgToSend.setColumns(10);

		Component horizontalStrut_2 = Box.createHorizontalStrut(20);
		panelSouth.add(horizontalStrut_2);

		btnSendMsg = new JButton("发送");
		btnSendMsg.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String msgContent = textFieldMsgToSend.getText();
				if (rdbtnNewRadioButton_pubChat.isSelected() && !rdbtnNewRadioButton_priChat.isSelected()) {// 选择公聊
					if (msgContent.length() > 0) {
						// 将消息文本框中的内容作为公聊消息发送给服务器
						ChatMessage chatMessage = new ChatMessage(localUserName, "", msgContent);
						try {

							synchronized (oos) {
								oos.writeObject(chatMessage);
								oos.flush();
							}

						} catch (IOException e1) {
							e1.printStackTrace();
						}
						// 在“消息记录”文本框中用蓝色显示发送的消息及发送时间
						String msgRecord = dateFormat.format(new Date()) + "说:\r\n" + msgContent + "\r\n";
						addMsgRecord(msgRecord, Color.blue, 12, false, false);

						// 将用户名和消息文本框中的内容清空
						textFieldUserName.setText("");
						textFieldMsgToSend.setText("");

					}
				} else if (!rdbtnNewRadioButton_pubChat.isSelected() && rdbtnNewRadioButton_priChat.isSelected()) {// 选择私聊
					// 获取私聊对象的名字
					targetUser = textFieldUserName.getText();
					// 获取私聊消息内容
					String targetMesage = textFieldMsgToSend.getText();

					if (targetUser.length() > 0) {
						// 创建私聊消息对象，并且发送给服务器
						ChatMessage privateChatMsg = new ChatMessage(localUserName, targetUser, targetMesage);
						try {

							synchronized (oos) {
								oos.writeObject(privateChatMsg);
								oos.flush();
							}

						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}

						// 在“消息记录”文本框中用红色显示发送的消息及发送时间
						String msgRecord = dateFormat.format(new Date()) + "说:\r\n" + targetMesage + "\r\n";
						addMsgRecord(msgRecord, Color.red, 12, false, false);

					} else {
						JOptionPane.showMessageDialog(Client.this, "私聊对象不能为空");
					}
				}

				textFieldMsgToSend.setText("");
			}
		});

		panelSouth.add(btnSendMsg);
		Component horizontalStrut_3 = Box.createHorizontalStrut(20);
		panelSouth.add(horizontalStrut_3);

		btnSendFile = new JButton("发送文件");
		btnSendFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if (btnSendFile.getText().equals("发送文件")) {

					String fileToAcceptUser = textFieldUserName.getText();
					msgMessage = textFieldMsgToSend.getText();
					JFileChooser jFileChooser = new JFileChooser();
					jFileChooser.setFileSelectionMode(jFileChooser.FILES_AND_DIRECTORIES);

					jFileChooser.showDialog(new Label(), "选择");
					File file = jFileChooser.getSelectedFile();
					if (file.isFile()) {
						fileName = file.getName();
						filePath = file.getAbsolutePath();
						fileSize = file.length();

						// 创建一条文件消息
						FileMessage fileMessage = new FileMessage(localUserName, fileToAcceptUser, fileName, "是否接受文件？",fileSize);
						try {

							synchronized (oos) {
								oos.writeObject(fileMessage);
								oos.flush();
							}

						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						System.out.println("文件消息已经发送，，，，，，，，，，，");
					} else if (file.isDirectory()) {
						JOptionPane.showMessageDialog(Client.this, "这是一个目录！");
					}
				}
			}
		});
		panelSouth.add(btnSendFile);
		// 将发送按钮设为不可用状态
		btnSendMsg.setEnabled(false);
		// 将文件按钮设为不可用状态
		btnSendFile.setEnabled(false);
		//文件传输进度条默认为隐藏
		jProgressBar.setVisible(false);
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

	// 后台监听线程
	class ListeningHandler implements Runnable {
		@Override
		public void run() {
			try {
				while (true) {
					Message msg = (Message) ois.readObject();
					if (msg instanceof UserStateMessage) {
						// 处理用户状态消息
						processUserStateMessage((UserStateMessage) msg);
					} else if (msg instanceof ChatMessage) {
						// 处理聊天消息
						processChatMessage((ChatMessage) msg);
					} else if (msg instanceof LoginEchoMessage) {
						// 处理用户登录反馈消息
						processLoginEchoMessage((LoginEchoMessage) msg);
					} else if (msg instanceof FileMessage) {
						// 处理文件消息
						processFileMessage((FileMessage) msg);
					} else if (msg instanceof EchoFileMessage) {
						// 处理文件回应消息
						processEchoFileMessage((EchoFileMessage) msg);
					} else if (msg instanceof ExceptionEchoMessage) {
						// 处理服务器返回的异常消息
						processEchoExcepMessage((ExceptionEchoMessage) msg);
					} else if (msg instanceof EchoOffLineFileMessage) {
						// 处理服务器发来的离线文件回馈消息
						processEchoOffLineFileMessage((EchoOffLineFileMessage) msg);
					} else if (msg instanceof OfflineFileMessage) {
						// 处理服务器发送来的离线文件消息
						processOfflineFileMessage((OfflineFileMessage) msg);
					} else {
						// 这种情况对应着用户发来的消息格式 错误，应该发消息提示用户
						System.err.println("用户发来的消息格式错误!");
					}
				}
			} catch (IOException e) {
				if (e.toString().endsWith("Connection reset")) {
					System.out.println("服务器端退出");
				} else {
					e.printStackTrace();
				}
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} finally {
				if (socket != null) {
					try {
						socket.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		// 处理服务器转发来的离线文件消息
		private void processOfflineFileMessage(OfflineFileMessage msg) {
			int offFileRevPort = Integer.parseInt(msg.getSrcUser());
			String fileName = msg.offLineMsgContent();
			long revOffFileSize=msg.getOffFileSize();

			if (JOptionPane.showConfirmDialog(null, "是否接受文件：" + fileName, "离线文件接受确认",
					JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION) {

				// 开启离线文件接受线程
				new Thread() {
					@Override
					public void run() {
						try {
							Socket offFileRevSocket = new Socket("localhost", offFileRevPort);
							DataInputStream dis = new DataInputStream(offFileRevSocket.getInputStream());
							DataOutputStream dos = new DataOutputStream(new FileOutputStream("D:\\" + fileName));
							ProgressMonitorInputStream pim = new ProgressMonitorInputStream(Client.this, "正在接受文件", dis);

							byte[] buf = new byte[1024 * 9];
							int len = 0;
							long sum = 0;
							jProgressBar.setVisible(true);
							while ((len = pim.read(buf)) != -1) {
								dos.write(buf, 0, len);
								sum+=len;
								updateJProgressBar(sum);
							}
							dos.flush();
							if (len == -1) {
								jProgressBar.setVisible(false);
								dis.close();
								dos.close();
								JOptionPane.showMessageDialog(Client.this, "文件已将保存在D盘下");
							}

						} catch (UnknownHostException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (FileNotFoundException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

					private void updateJProgressBar(long sum) {
						long present = (sum * 100 / revOffFileSize);
						System.err.println("传输百分比：  " + present + "%");						
						jProgressBar.setString(present + "%");
						jProgressBar.setValue((int) present);					
					}
				}.start();
			} else {
				return;
			}

		}

		// 处理服务器发来的离线文件发送询问消息
		private void processEchoOffLineFileMessage(EchoOffLineFileMessage msg) {

			int offFilePort = Integer.parseInt(msg.getOffLinePort());

			if (JOptionPane.showConfirmDialog(Client.this, "目标用户不在线，是否发送离线文件?", "离线文件发送确认",
					JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION) {
				// 连接离线端口服务器，创建新线程来向服务器发送文件
				try {
					new Thread() {
						Socket offFileSendSocket = new Socket("localhost", offFilePort);

						@Override
						public void run() {
							try {
								DataInputStream dis = new DataInputStream(new FileInputStream(filePath));
								DataOutputStream dos = new DataOutputStream(offFileSendSocket.getOutputStream());

								// 创建进度条线程对象
								// ProgressBarThread pBarThread=new ProgressBarThread(fileSize);
								// 开启线程，刷新进度条
								// new Thread(pBarThread).start();
								//ProgressMonitorInputStream pim = new ProgressMonitorInputStream(Client.this, "正在发送文件",dis);
								byte[] buf = new byte[1024 * 9];
								int len = 0;
								long sum=0;

								jProgressBar.setVisible(true);//将进度条展示设为可见
								while ((len = dis.read(buf)) != -1) {
									dos.write(buf, 0, len);
									sum+=len;
									updateJProgressBar(sum);
								}
								dos.flush();
								if (len == -1) {
									jProgressBar.setVisible(false);
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

						private void updateJProgressBar(long sum) {
							long present = (sum * 100 / fileSize);
							System.err.println("传输百分比：  " + present + "%");						
							jProgressBar.setString(present + "%");
							jProgressBar.setValue((int) present);					
						}
					}.start();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		}

		// 处理服务器返回的异常消息
		private void processEchoExcepMessage(ExceptionEchoMessage msg) {
			String echoExcepMsg = msg.getExceptionEchoMessage();
			JOptionPane.showMessageDialog(Client.this, echoExcepMsg);
		}

		// 处理文件回应消息
		private void processEchoFileMessage(EchoFileMessage msg) {

			String srcUser = msg.getSrcUser();
			String echoMsg = msg.getEchoFileMessage();
			if (echoMsg.equals("no")) {
				// 向消息记录框中添加一条目标用户拒绝接受文件的消息
				String echoFileMsg = dateFormat.format(new Date()) + "  目标用户拒绝接受文件\r\n";
				addMsgRecord(echoFileMsg, Color.YELLOW, 12, true, false);
				return;
			} else if (echoMsg.equals("ok")) {
				// 在消息记录文本框中添加一条目标用户同意接受文件的消息
				String echoFileMsg = dateFormat.format(new Date()) + "  目标用户同意接受文件\r\n";
				addMsgRecord(echoFileMsg, Color.green, 12, true, false);
				fileSocketPort = Integer.parseInt(srcUser);

				// 开启线程给在线目标用户发送文件
				new Thread() {
					@Override
					public void run() {
						try {
							// 与文件接受者建立socket连接
							Socket fileSocket = new Socket("localhost", fileSocketPort);

							// 创建带缓冲的字节流读取本地文件
							DataInputStream dis = new DataInputStream(new FileInputStream(filePath));
							// 封装socket的输出流
							DataOutputStream dos = new DataOutputStream(fileSocket.getOutputStream());

							jProgressBar.setVisible(true);//将进度条置为可见状态
							byte[] buf = new byte[1024 * 9];
							int len = 0;
							long sum = 0;
							while ((len = dis.read(buf)) != -1) {
								dos.write(buf, 0, len);
								sum = sum + len;
								updateJProgressBar(sum);
							}
							dos.flush();
							if (len == -1) {// 文件传输结束
								jProgressBar.setVisible(false);//发送完毕，隐藏进度条
								dis.close();
								dos.close();
								JOptionPane.showMessageDialog(Client.this, "文件发送完毕！");
							}
						} catch (HeadlessException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (UnknownHostException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (FileNotFoundException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

					// 更新进度条
					private void updateJProgressBar(long sum) {
						long present = (sum * 100 / fileSize);
						System.err.println("传输百分比：  " + present + "%");						
						jProgressBar.setString(present + "%");
						jProgressBar.setValue((int) present);				
					}
				}.start();

			}

		}

		// 处理服务器转发来的文件请求消息
		private void processFileMessage(FileMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String fileName = msg.getFileName();
			long revFileSize = msg.getFileSize();
			String dialogMessage = "用户" + srcUser + "发送了文件：" + fileName + "是否接受？";
			// 在消息记录文本框中用红色添加xxx用户发送了一个xxx文件的消息
			String fileMsgRecord = dateFormat.format(new Date()) + "   用户 ：" + srcUser + "  发送了文件：" + fileName+"大小："+revFileSize;
			addMsgRecord(fileMsgRecord, Color.CYAN, 12, true, false);

			if (JOptionPane.showConfirmDialog(Client.this, dialogMessage, "文件接受确认",
					JOptionPane.YES_NO_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
				// 给文件发送方发送一条同意接受文件的回应消息
				// 创建一条私聊消息，告诉文件发送者该文件接受者的监听端口,为方便将该用户的端口作为该端口的用户名发送
				// 为防止与聊天消息内容混淆，在这里将聊天消息设为port，作为标记
				EchoFileMessage echoFileMessage = new EchoFileMessage("8888", srcUser, "ok");
				try {
					synchronized (oos) {
						oos.writeObject(echoFileMessage);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				try {
					// 开启文件接受线程
					ServerSocket fileServerSocket = new ServerSocket(8888);
					// 创建并启动接受用户文件发送链接线程
					new Thread() {
						@Override
						public void run() {
							while (true) {
								try {
									// 接受文件发送端的连接请求
									Socket fileSocket = fileServerSocket.accept();
									DataInputStream dis = new DataInputStream(fileSocket.getInputStream());
									// DataInputStream dis=new DataInputStream(new
									// ProgressMonitorInputStream(Client.this, "接受文件",
									// fileSocket.getInputStream()));
									DataOutputStream dos = new DataOutputStream(
											new FileOutputStream("D:\\" + fileName));

									//ProgressMonitorInputStream pmi = new ProgressMonitorInputStream(Client.this, "接受文件",dis);

									jProgressBar.setVisible(true);//将进度条置为可见状态
									byte[] buf = new byte[1024 * 9];
									int len = 0;
									long sum=0;
									while ((len = dis.read(buf)) != -1) {
										dos.write(buf, 0, len);
										sum+=len;
										updateJProgressBar(sum);
									}
									dos.flush();
									if (len == -1) {
										jProgressBar.setVisible(false);
										dis.close();
										dos.close();
										JOptionPane.showMessageDialog(Client.this, "文件已经保存在D盘！");
									}
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}

							}
							
						}

						private void updateJProgressBar(long sum) {
							long present = (sum * 100 / revFileSize);
							System.err.println("传输百分比：  " + present + "%");						
							jProgressBar.setString(present + "%");
							jProgressBar.setValue((int) present);				
						}

					}.start();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			} else {
				// 给文件发送方发送一条拒绝接受文件的回应消息
				EchoFileMessage echoFileMessage = new EchoFileMessage(localUserName, srcUser, "no");
				try {
					synchronized (oos) {
						oos.writeObject(echoFileMessage);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		// 处理用户登录反馈消息
		private void processLoginEchoMessage(LoginEchoMessage msg) {
			// 接受服务器发送回来的登录验证消息
			String loginEchoMessage = msg.getLoginEchoString();
			if (loginEchoMessage.equals("ok")) {
				JOptionPane.showMessageDialog(Client.this, "登录成功");

				// 向服务器发送用户上线消息
				UserStateMessage userStateMessage = new UserStateMessage(localUserName, "", true);

				try {
					synchronized (oos) {
						oos.writeObject(userStateMessage);
						oos.flush();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				// 将用户名文本框中的内容置空
				textFieldUserName.setText(null);
				Client.this.setTitle(localUserName);

				// 在“消息记录”文本框中用红色添加“XX时间登录成功”的信息
				String msgRecord = dateFormat.format(new Date()) + " 登录成功\r\n";
				addMsgRecord(msgRecord, Color.red, 12, false, false);

				// 将“登录”按钮设为“退出”按钮
				btnLogin.setText("退出");
				// 将发送文件按钮设为可用状态
				btnSendFile.setEnabled(true);
				// 将发送消息按钮设为可用状态
				btnSendMsg.setEnabled(true);

				// 隐藏注册按钮
				btnNewButton_register.setEnabled(false);

				// 隐藏密码选项
				lblPwd.setVisible(false);
				// 隐藏密码文本框
				passwordFieldPwd.setVisible(false);

			} else if (loginEchoMessage.equals("warning")) {
				JOptionPane.showMessageDialog(Client.this, "用户名或密码错误");
			} else {
				System.out.println("见鬼啦，，，");
			}

		}

		// 处理用户状态消息
		private void processUserStateMessage(UserStateMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			if (msg.isUserOnline()) {
				if (msg.isPubUserStateMessage()) { // 新用户上线消息
					// 用绿色文字将用户名和用户上线时间添加到“消息记录”文本框中
					final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "上线了!\r\n";
					addMsgRecord(msgRecord, Color.green, 12, false, false);
					// 在“在线用户”列表中增加新上线的用户名
					onlineUserDlm.addElement(srcUser);
				}
				if (dstUser.equals(localUserName)) { // 用户在线消息
					onlineUserDlm.addElement(srcUser);
				}
			} else if (msg.isUserOffline()) { // 用户下线消息
				if (onlineUserDlm.contains(srcUser)) {
					// 用绿色文字将用户名和用户下线时间添加到“消息记录”文本框中
					final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "下线了!\r\n";
					addMsgRecord(msgRecord, Color.green, 12, false, false);
					// 在“在线用户”列表中删除下线的用户名
					onlineUserDlm.removeElement(srcUser);
				}
			}
		}

		// 处理服务器转发来的私聊和公聊消息
		private void processChatMessage(ChatMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String msgContent = msg.getMsgContent();

			if (msg.isPubChatMessage() || dstUser.equals(localUserName)) {// 处理公聊消息
				// 用红色文字将收到消息的时间、发送消息的用户名和消息内容添加到“消息记录”文本框中
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "说: \r\n" + msgContent
						+ "\r\n";
				addMsgRecord(msgRecord, Color.red, 12, false, false);
			} else if ((!msg.isPubChatMessage()) && (dstUser.equals(localUserName))) {// 处理私聊消息
				if (!msgContent.equals("port")) {
					// 用绿色文字将收到消息的时间、发送消息的用户名和消息内容添加到“消息记录”文本框中
					final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "说: \r\n" + msgContent
							+ "\r\n";
					addMsgRecord(msgRecord, Color.green, 12, false, false);

				} else if (msgContent.equals("port")) {
					// 获取文件接受者的端口
					fileSocketPort = Integer.parseInt(srcUser);
				}
			}
		}
	}

	// 文件传输进度条监视进程
	class ProgressBarThread implements Runnable {
		// private ArrayList<Integer> proList = new ArrayList<Integer>();
		private long progress;// 当前进度
		private long totalSize;// 总大小
		private boolean run = true;

		public ProgressBarThread(long fileSize) {
			this.totalSize = fileSize;
		}

		/*
		 * // 更新进度 public void updateProgress(int prograss) { synchronized
		 * (this.proList) { if (this.run) { this.proList.add(prograss);//将当前进度添加到进度列表尾部
		 * this.proList.notify(); } } }
		 */

		// 更新进度条
		public void updateJProgressBar(int len) {

		}

		// 关闭进度条
		private void finish() {
			this.run = false;
		}

		@Override
		public void run() {
			System.out.println("进度条，，，，，，，，，，，，，，，");
			System.out.println("读到的字节数--》》" + progress);
			long persent = progress / totalSize * 100;
			jProgressBar.setValue((int) persent);
			// TODO 更新进度条
			System.err.println("当前进度：" + (this.progress / this.totalSize * 100) + "%");

			System.err.println("发送完成");
		}
	}

}
