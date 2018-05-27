
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
	private String msgMessage;// �����͵���Ϣ����

	private String targetUser;// ˽�Ķ���
	private String fileName;// �����͵��ļ���
	private String filePath;// �����͵��ļ�·��
	private long fileSize;// �����͵��ļ���С

	// �������û��б�ListModel��,����ά���������û��б�����ʾ������
	private final DefaultListModel<String> onlineUserDlm = new DefaultListModel<String>();
	// ���ڿ���ʱ����Ϣ��ʾ��ʽ
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

		btnLogin = new JButton("��¼");
		btnLogin.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (btnLogin.getText().equals("��¼")) {
					localUserName = textFieldUserName.getText().trim();
					passwd = String.valueOf(passwordFieldPwd.getPassword());

					if (btnLogin.getText().equals("��¼")) {
						if (localUserName.length() > 0) {
							if (passwd.length() > 0) {
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

									SSLContext sslContext = SSLContext.getInstance("TLS");
									sslContext.init(null, tmf.getTrustManagers(), null);
									// ����SSLSocket����
									SSLSocketFactory factory = sslContext.getSocketFactory();
									// �����������socket����
									socket = (SSLSocket) factory.createSocket("localhost", port);

									oos = new ObjectOutputStream(socket.getOutputStream());
									ois = new ObjectInputStream(socket.getInputStream());
								} catch (UnknownHostException e1) {
									JOptionPane.showMessageDialog(Client.this, "����������δ�ҵ�");
									// TODO Auto-generated catch block
									e1.printStackTrace();
									System.exit(0);
								} catch (IOException e1) {
									JOptionPane.showMessageDialog(Client.this, "������δ����");
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

								// ������������̨�����߳�
								new Thread(new ListeningHandler()).start();
								// ������������û���¼������Ϣ
								LoginMessage loginMessage = new LoginMessage(localUserName, "", passwd);
								// ������������û���¼������Ϣ����
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
								JOptionPane.showMessageDialog(Client.this, "���벻��Ϊ��");
							}
						} else {
							JOptionPane.showMessageDialog(Client.this, "�û�������Ϊ��");
						}
					}
				} else if (btnLogin.getText().equals("�˳�")) {
					if (JOptionPane.showConfirmDialog(Client.this, "�Ƿ��˳�?", "�˳�ȷ��",
							JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION) {
						// ������������û�������Ϣ
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

		btnNewButton_register = new JButton("ע��");
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

		btnSendMsg = new JButton("����");
		btnSendMsg.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String msgContent = textFieldMsgToSend.getText();
				if (rdbtnNewRadioButton_pubChat.isSelected() && !rdbtnNewRadioButton_priChat.isSelected()) {// ѡ����
					if (msgContent.length() > 0) {
						// ����Ϣ�ı����е�������Ϊ������Ϣ���͸�������
						ChatMessage chatMessage = new ChatMessage(localUserName, "", msgContent);
						try {

							synchronized (oos) {
								oos.writeObject(chatMessage);
								oos.flush();
							}

						} catch (IOException e1) {
							e1.printStackTrace();
						}
						// �ڡ���Ϣ��¼���ı���������ɫ��ʾ���͵���Ϣ������ʱ��
						String msgRecord = dateFormat.format(new Date()) + "˵:\r\n" + msgContent + "\r\n";
						addMsgRecord(msgRecord, Color.blue, 12, false, false);

						// ���û�������Ϣ�ı����е��������
						textFieldUserName.setText("");
						textFieldMsgToSend.setText("");

					}
				} else if (!rdbtnNewRadioButton_pubChat.isSelected() && rdbtnNewRadioButton_priChat.isSelected()) {// ѡ��˽��
					// ��ȡ˽�Ķ��������
					targetUser = textFieldUserName.getText();
					// ��ȡ˽����Ϣ����
					String targetMesage = textFieldMsgToSend.getText();

					if (targetUser.length() > 0) {
						// ����˽����Ϣ���󣬲��ҷ��͸�������
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

						// �ڡ���Ϣ��¼���ı������ú�ɫ��ʾ���͵���Ϣ������ʱ��
						String msgRecord = dateFormat.format(new Date()) + "˵:\r\n" + targetMesage + "\r\n";
						addMsgRecord(msgRecord, Color.red, 12, false, false);

					} else {
						JOptionPane.showMessageDialog(Client.this, "˽�Ķ�����Ϊ��");
					}
				}

				textFieldMsgToSend.setText("");
			}
		});

		panelSouth.add(btnSendMsg);
		Component horizontalStrut_3 = Box.createHorizontalStrut(20);
		panelSouth.add(horizontalStrut_3);

		btnSendFile = new JButton("�����ļ�");
		btnSendFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if (btnSendFile.getText().equals("�����ļ�")) {

					String fileToAcceptUser = textFieldUserName.getText();
					msgMessage = textFieldMsgToSend.getText();
					JFileChooser jFileChooser = new JFileChooser();
					jFileChooser.setFileSelectionMode(jFileChooser.FILES_AND_DIRECTORIES);

					jFileChooser.showDialog(new Label(), "ѡ��");
					File file = jFileChooser.getSelectedFile();
					if (file.isFile()) {
						fileName = file.getName();
						filePath = file.getAbsolutePath();
						fileSize = file.length();

						// ����һ���ļ���Ϣ
						FileMessage fileMessage = new FileMessage(localUserName, fileToAcceptUser, fileName, "�Ƿ�����ļ���",fileSize);
						try {

							synchronized (oos) {
								oos.writeObject(fileMessage);
								oos.flush();
							}

						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						System.out.println("�ļ���Ϣ�Ѿ����ͣ���������������������");
					} else if (file.isDirectory()) {
						JOptionPane.showMessageDialog(Client.this, "����һ��Ŀ¼��");
					}
				}
			}
		});
		panelSouth.add(btnSendFile);
		// �����Ͱ�ť��Ϊ������״̬
		btnSendMsg.setEnabled(false);
		// ���ļ���ť��Ϊ������״̬
		btnSendFile.setEnabled(false);
		//�ļ����������Ĭ��Ϊ����
		jProgressBar.setVisible(false);
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

	// ��̨�����߳�
	class ListeningHandler implements Runnable {
		@Override
		public void run() {
			try {
				while (true) {
					Message msg = (Message) ois.readObject();
					if (msg instanceof UserStateMessage) {
						// �����û�״̬��Ϣ
						processUserStateMessage((UserStateMessage) msg);
					} else if (msg instanceof ChatMessage) {
						// ����������Ϣ
						processChatMessage((ChatMessage) msg);
					} else if (msg instanceof LoginEchoMessage) {
						// �����û���¼������Ϣ
						processLoginEchoMessage((LoginEchoMessage) msg);
					} else if (msg instanceof FileMessage) {
						// �����ļ���Ϣ
						processFileMessage((FileMessage) msg);
					} else if (msg instanceof EchoFileMessage) {
						// �����ļ���Ӧ��Ϣ
						processEchoFileMessage((EchoFileMessage) msg);
					} else if (msg instanceof ExceptionEchoMessage) {
						// ������������ص��쳣��Ϣ
						processEchoExcepMessage((ExceptionEchoMessage) msg);
					} else if (msg instanceof EchoOffLineFileMessage) {
						// ��������������������ļ�������Ϣ
						processEchoOffLineFileMessage((EchoOffLineFileMessage) msg);
					} else if (msg instanceof OfflineFileMessage) {
						// ����������������������ļ���Ϣ
						processOfflineFileMessage((OfflineFileMessage) msg);
					} else {
						// ���������Ӧ���û���������Ϣ��ʽ ����Ӧ�÷���Ϣ��ʾ�û�
						System.err.println("�û���������Ϣ��ʽ����!");
					}
				}
			} catch (IOException e) {
				if (e.toString().endsWith("Connection reset")) {
					System.out.println("���������˳�");
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

		// ���������ת�����������ļ���Ϣ
		private void processOfflineFileMessage(OfflineFileMessage msg) {
			int offFileRevPort = Integer.parseInt(msg.getSrcUser());
			String fileName = msg.offLineMsgContent();
			long revOffFileSize=msg.getOffFileSize();

			if (JOptionPane.showConfirmDialog(null, "�Ƿ�����ļ���" + fileName, "�����ļ�����ȷ��",
					JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION) {

				// ���������ļ������߳�
				new Thread() {
					@Override
					public void run() {
						try {
							Socket offFileRevSocket = new Socket("localhost", offFileRevPort);
							DataInputStream dis = new DataInputStream(offFileRevSocket.getInputStream());
							DataOutputStream dos = new DataOutputStream(new FileOutputStream("D:\\" + fileName));
							ProgressMonitorInputStream pim = new ProgressMonitorInputStream(Client.this, "���ڽ����ļ�", dis);

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
								JOptionPane.showMessageDialog(Client.this, "�ļ��ѽ�������D����");
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
						System.err.println("����ٷֱȣ�  " + present + "%");						
						jProgressBar.setString(present + "%");
						jProgressBar.setValue((int) present);					
					}
				}.start();
			} else {
				return;
			}

		}

		// ��������������������ļ�����ѯ����Ϣ
		private void processEchoOffLineFileMessage(EchoOffLineFileMessage msg) {

			int offFilePort = Integer.parseInt(msg.getOffLinePort());

			if (JOptionPane.showConfirmDialog(Client.this, "Ŀ���û������ߣ��Ƿ��������ļ�?", "�����ļ�����ȷ��",
					JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION) {
				// �������߶˿ڷ��������������߳���������������ļ�
				try {
					new Thread() {
						Socket offFileSendSocket = new Socket("localhost", offFilePort);

						@Override
						public void run() {
							try {
								DataInputStream dis = new DataInputStream(new FileInputStream(filePath));
								DataOutputStream dos = new DataOutputStream(offFileSendSocket.getOutputStream());

								// �����������̶߳���
								// ProgressBarThread pBarThread=new ProgressBarThread(fileSize);
								// �����̣߳�ˢ�½�����
								// new Thread(pBarThread).start();
								//ProgressMonitorInputStream pim = new ProgressMonitorInputStream(Client.this, "���ڷ����ļ�",dis);
								byte[] buf = new byte[1024 * 9];
								int len = 0;
								long sum=0;

								jProgressBar.setVisible(true);//��������չʾ��Ϊ�ɼ�
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
							System.err.println("����ٷֱȣ�  " + present + "%");						
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

		// ������������ص��쳣��Ϣ
		private void processEchoExcepMessage(ExceptionEchoMessage msg) {
			String echoExcepMsg = msg.getExceptionEchoMessage();
			JOptionPane.showMessageDialog(Client.this, echoExcepMsg);
		}

		// �����ļ���Ӧ��Ϣ
		private void processEchoFileMessage(EchoFileMessage msg) {

			String srcUser = msg.getSrcUser();
			String echoMsg = msg.getEchoFileMessage();
			if (echoMsg.equals("no")) {
				// ����Ϣ��¼�������һ��Ŀ���û��ܾ������ļ�����Ϣ
				String echoFileMsg = dateFormat.format(new Date()) + "  Ŀ���û��ܾ������ļ�\r\n";
				addMsgRecord(echoFileMsg, Color.YELLOW, 12, true, false);
				return;
			} else if (echoMsg.equals("ok")) {
				// ����Ϣ��¼�ı��������һ��Ŀ���û�ͬ������ļ�����Ϣ
				String echoFileMsg = dateFormat.format(new Date()) + "  Ŀ���û�ͬ������ļ�\r\n";
				addMsgRecord(echoFileMsg, Color.green, 12, true, false);
				fileSocketPort = Integer.parseInt(srcUser);

				// �����̸߳�����Ŀ���û������ļ�
				new Thread() {
					@Override
					public void run() {
						try {
							// ���ļ������߽���socket����
							Socket fileSocket = new Socket("localhost", fileSocketPort);

							// ������������ֽ�����ȡ�����ļ�
							DataInputStream dis = new DataInputStream(new FileInputStream(filePath));
							// ��װsocket�������
							DataOutputStream dos = new DataOutputStream(fileSocket.getOutputStream());

							jProgressBar.setVisible(true);//����������Ϊ�ɼ�״̬
							byte[] buf = new byte[1024 * 9];
							int len = 0;
							long sum = 0;
							while ((len = dis.read(buf)) != -1) {
								dos.write(buf, 0, len);
								sum = sum + len;
								updateJProgressBar(sum);
							}
							dos.flush();
							if (len == -1) {// �ļ��������
								jProgressBar.setVisible(false);//������ϣ����ؽ�����
								dis.close();
								dos.close();
								JOptionPane.showMessageDialog(Client.this, "�ļ�������ϣ�");
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

					// ���½�����
					private void updateJProgressBar(long sum) {
						long present = (sum * 100 / fileSize);
						System.err.println("����ٷֱȣ�  " + present + "%");						
						jProgressBar.setString(present + "%");
						jProgressBar.setValue((int) present);				
					}
				}.start();

			}

		}

		// ���������ת�������ļ�������Ϣ
		private void processFileMessage(FileMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String fileName = msg.getFileName();
			long revFileSize = msg.getFileSize();
			String dialogMessage = "�û�" + srcUser + "�������ļ���" + fileName + "�Ƿ���ܣ�";
			// ����Ϣ��¼�ı������ú�ɫ���xxx�û�������һ��xxx�ļ�����Ϣ
			String fileMsgRecord = dateFormat.format(new Date()) + "   �û� ��" + srcUser + "  �������ļ���" + fileName+"��С��"+revFileSize;
			addMsgRecord(fileMsgRecord, Color.CYAN, 12, true, false);

			if (JOptionPane.showConfirmDialog(Client.this, dialogMessage, "�ļ�����ȷ��",
					JOptionPane.YES_NO_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
				// ���ļ����ͷ�����һ��ͬ������ļ��Ļ�Ӧ��Ϣ
				// ����һ��˽����Ϣ�������ļ������߸��ļ������ߵļ����˿�,Ϊ���㽫���û��Ķ˿���Ϊ�ö˿ڵ��û�������
				// Ϊ��ֹ��������Ϣ���ݻ����������ｫ������Ϣ��Ϊport����Ϊ���
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
					// �����ļ������߳�
					ServerSocket fileServerSocket = new ServerSocket(8888);
					// ���������������û��ļ����������߳�
					new Thread() {
						@Override
						public void run() {
							while (true) {
								try {
									// �����ļ����Ͷ˵���������
									Socket fileSocket = fileServerSocket.accept();
									DataInputStream dis = new DataInputStream(fileSocket.getInputStream());
									// DataInputStream dis=new DataInputStream(new
									// ProgressMonitorInputStream(Client.this, "�����ļ�",
									// fileSocket.getInputStream()));
									DataOutputStream dos = new DataOutputStream(
											new FileOutputStream("D:\\" + fileName));

									//ProgressMonitorInputStream pmi = new ProgressMonitorInputStream(Client.this, "�����ļ�",dis);

									jProgressBar.setVisible(true);//����������Ϊ�ɼ�״̬
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
										JOptionPane.showMessageDialog(Client.this, "�ļ��Ѿ�������D�̣�");
									}
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}

							}
							
						}

						private void updateJProgressBar(long sum) {
							long present = (sum * 100 / revFileSize);
							System.err.println("����ٷֱȣ�  " + present + "%");						
							jProgressBar.setString(present + "%");
							jProgressBar.setValue((int) present);				
						}

					}.start();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			} else {
				// ���ļ����ͷ�����һ���ܾ������ļ��Ļ�Ӧ��Ϣ
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

		// �����û���¼������Ϣ
		private void processLoginEchoMessage(LoginEchoMessage msg) {
			// ���ܷ��������ͻ����ĵ�¼��֤��Ϣ
			String loginEchoMessage = msg.getLoginEchoString();
			if (loginEchoMessage.equals("ok")) {
				JOptionPane.showMessageDialog(Client.this, "��¼�ɹ�");

				// ������������û�������Ϣ
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

				// ���û����ı����е������ÿ�
				textFieldUserName.setText(null);
				Client.this.setTitle(localUserName);

				// �ڡ���Ϣ��¼���ı������ú�ɫ��ӡ�XXʱ���¼�ɹ�������Ϣ
				String msgRecord = dateFormat.format(new Date()) + " ��¼�ɹ�\r\n";
				addMsgRecord(msgRecord, Color.red, 12, false, false);

				// ������¼����ť��Ϊ���˳�����ť
				btnLogin.setText("�˳�");
				// �������ļ���ť��Ϊ����״̬
				btnSendFile.setEnabled(true);
				// ��������Ϣ��ť��Ϊ����״̬
				btnSendMsg.setEnabled(true);

				// ����ע�ᰴť
				btnNewButton_register.setEnabled(false);

				// ��������ѡ��
				lblPwd.setVisible(false);
				// ���������ı���
				passwordFieldPwd.setVisible(false);

			} else if (loginEchoMessage.equals("warning")) {
				JOptionPane.showMessageDialog(Client.this, "�û������������");
			} else {
				System.out.println("������������");
			}

		}

		// �����û�״̬��Ϣ
		private void processUserStateMessage(UserStateMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			if (msg.isUserOnline()) {
				if (msg.isPubUserStateMessage()) { // ���û�������Ϣ
					// ����ɫ���ֽ��û������û�����ʱ����ӵ�����Ϣ��¼���ı�����
					final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "������!\r\n";
					addMsgRecord(msgRecord, Color.green, 12, false, false);
					// �ڡ������û����б������������ߵ��û���
					onlineUserDlm.addElement(srcUser);
				}
				if (dstUser.equals(localUserName)) { // �û�������Ϣ
					onlineUserDlm.addElement(srcUser);
				}
			} else if (msg.isUserOffline()) { // �û�������Ϣ
				if (onlineUserDlm.contains(srcUser)) {
					// ����ɫ���ֽ��û������û�����ʱ����ӵ�����Ϣ��¼���ı�����
					final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "������!\r\n";
					addMsgRecord(msgRecord, Color.green, 12, false, false);
					// �ڡ������û����б���ɾ�����ߵ��û���
					onlineUserDlm.removeElement(srcUser);
				}
			}
		}

		// ���������ת������˽�ĺ͹�����Ϣ
		private void processChatMessage(ChatMessage msg) {
			String srcUser = msg.getSrcUser();
			String dstUser = msg.getDstUser();
			String msgContent = msg.getMsgContent();

			if (msg.isPubChatMessage() || dstUser.equals(localUserName)) {// ��������Ϣ
				// �ú�ɫ���ֽ��յ���Ϣ��ʱ�䡢������Ϣ���û�������Ϣ������ӵ�����Ϣ��¼���ı�����
				final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "˵: \r\n" + msgContent
						+ "\r\n";
				addMsgRecord(msgRecord, Color.red, 12, false, false);
			} else if ((!msg.isPubChatMessage()) && (dstUser.equals(localUserName))) {// ����˽����Ϣ
				if (!msgContent.equals("port")) {
					// ����ɫ���ֽ��յ���Ϣ��ʱ�䡢������Ϣ���û�������Ϣ������ӵ�����Ϣ��¼���ı�����
					final String msgRecord = dateFormat.format(new Date()) + " " + srcUser + "˵: \r\n" + msgContent
							+ "\r\n";
					addMsgRecord(msgRecord, Color.green, 12, false, false);

				} else if (msgContent.equals("port")) {
					// ��ȡ�ļ������ߵĶ˿�
					fileSocketPort = Integer.parseInt(srcUser);
				}
			}
		}
	}

	// �ļ�������������ӽ���
	class ProgressBarThread implements Runnable {
		// private ArrayList<Integer> proList = new ArrayList<Integer>();
		private long progress;// ��ǰ����
		private long totalSize;// �ܴ�С
		private boolean run = true;

		public ProgressBarThread(long fileSize) {
			this.totalSize = fileSize;
		}

		/*
		 * // ���½��� public void updateProgress(int prograss) { synchronized
		 * (this.proList) { if (this.run) { this.proList.add(prograss);//����ǰ������ӵ������б�β��
		 * this.proList.notify(); } } }
		 */

		// ���½�����
		public void updateJProgressBar(int len) {

		}

		// �رս�����
		private void finish() {
			this.run = false;
		}

		@Override
		public void run() {
			System.out.println("������������������������������������");
			System.out.println("�������ֽ���--����" + progress);
			long persent = progress / totalSize * 100;
			jProgressBar.setValue((int) persent);
			// TODO ���½�����
			System.err.println("��ǰ���ȣ�" + (this.progress / this.totalSize * 100) + "%");

			System.err.println("�������");
		}
	}

}
