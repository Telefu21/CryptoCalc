package CryptoCalculator;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JButton;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;

import javax.swing.JTextArea;
import javax.swing.JTabbedPane;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;

import javax.swing.JTextField;
import javax.swing.border.EtchedBorder;
import javax.swing.JPasswordField;
import javax.swing.JLabel;
import javax.swing.JCheckBox;
import java.awt.Toolkit;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.Font;
import java.awt.event.ItemListener;
import java.awt.event.ItemEvent;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import CryptoCalculator.CRC.Parameters;

import javax.swing.JRadioButton;
import javax.swing.ButtonGroup;

public class MainFrame extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	protected static final int COMBO_INDEX_SYMETRIC_CRYPTO_ENCRYPT = 0;
	protected static final int COMBO_INDEX_SYMETRIC_CRYPTO_DECRYPT = 1;
	protected static final int COMBO_INDEX_ASYMETRIC_CRYPTO_ENCRYPT = 2;
	protected static final int COMBO_INDEX_ASYMETRIC_CRYPTO_DECRYPT = 3;

	private static final int CERT_ATTRB_COLUMN_ROOT = 0;
	private static final int CERT_ATTRB_COLUMN_INTERMEDIATE = 1;
	private static final int CERT_ATTRB_COLUMN_END_ENTITY = 2;

	private static final int COMBO_INDEX_CERT_KEY_METHOD_RSA_1024 = 0;
	private static final int COMBO_INDEX_CERT_KEY_METHOD_RSA_2048 = 1;
	private static final int COMBO_INDEX_CERT_KEY_METHOD_RSA_4096 = 2;
	private static final int COMBO_INDEX_CERT_KEY_METHOD_SELECT_KEY_FILE = 3;
	private static final int COMBO_INDEX_CERT_KEY_METHOD_FILE_SELECTED = 4;

	private static final int GENERATE_CERTIFICATE_RET_STR_INDEX_CMD_RET = 0;
	private static final int GENERATE_CERTIFICATE_RET_STR_INDEX_CERTFILE = 1;
	private static final int GENERATE_CERTIFICATE_RET_STR_INDEX_CERTKEYFILE = 2;
	private static final int GENERATE_CERTIFICATE_RET_STR_INDEX_CERTCSRFILE = 3;
	
	private static final int FORMAT_CONVERSION_SELECT_FILE_OPERATION = 0;
	private static final int FORMAT_CONVERSION_VIEW_CERT_FILE = 1;
	private static final int FORMAT_CONVERSION_VIEW_CRL_FILE = 2;
	private static final int FORMAT_CONVERSION_VIEW_RSA_PRIV_KEY_FILE = 3;
	private static final int FORMAT_CONVERSION_VIEW_RSA_PUB_KEY_FILE = 4;
	private static final int FORMAT_CONVERSION_VIEW_PRIV_EC_KEY_FILE = 5;
	private static final int FORMAT_CONVERSION_VIEW_PUB_EC_KEY_FILE = 6;	
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_DER_CERT = 7;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_PEM_CERT = 8;
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_DER_CRL = 9;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_PEM_CRL = 10;
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_DER_RSA_PRIV = 11;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_PEM_RSA_PRIV = 12;
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_DER_RSA_PUB = 13;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_PEM_RSA_PUB = 14;
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_DER_ECC_PRIV = 15;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_PEM_ECC_PRIV = 16;
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_DER_ECC_PUB = 17;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_PEM_ECC_PUB = 18;
	private static final int FORMAT_CONVERSION_CONVERT_TEXT_TO_BASE64 = 19;
	private static final int FORMAT_CONVERSION_CONVERT_BASE64_TO_TEXT = 20;
	private static final int FORMAT_CONVERSION_CONVERT_PEM_TO_ASN1 = 21;
	private static final int FORMAT_CONVERSION_CONVERT_DER_TO_ASN1 = 22;

	private static final int CRC_PREDEFINED_PARAMS_CRC8 = 0;
	private static final int CRC_PREDEFINED_PARAMS_CRC16 = 1;
	private static final int CRC_PREDEFINED_PARAMS_CRC32 = 2;
	private static final int CRC_PREDEFINED_PARAMS_CRC64 = 3;
	
	private String previousTextAreaEncryptOutput = "";
	private String certKeyFile[] = {"", "", ""};
	
	private JPanel mainPane;
	private JTextField txtEncryptDecryptFileInput = new JTextField();
	private MainFrame selfInstance;
	private JTextField txtEncryptDecryptFileOutput = new JTextField();
	private CommandLineInterpretor cmdInterpretor = new  CommandLineInterpretor();
	private JPasswordField pwdEncryptAddPassPhrase = new JPasswordField();
	private JTextField txtAsymetricKeyFile = new JTextField();;
	private JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
	private JPanel encrypt = new JPanel();
	private JPanel groupBoxEncryptText = new JPanel();
	private JTextArea textAreaEncryptInput = new JTextArea();
	private JTextArea textAreaEncryptOutput = new JTextArea();
	private JPanel groupBoxEncryptFiles = new JPanel();
	private JButton btnBrowseEncrptyDecryptInput = new JButton("Browse");
	private JButton btnBrowseEncrptyDecryptOutput = new JButton("Browse");
	private JButton btnStartFileEncrypt = new JButton("Start File  Encryption");
	private JPanel groupBoxEncryptSymetricParams = new JPanel();
	private JComboBox<String> comboEncryptCiphers = new JComboBox<String>();
	private JLabel lblEncryptAlgorithm = new JLabel("Cipher:");
	private JCheckBox chckbxEncryptAddSalt = new JCheckBox("Add Salt");
	private JLabel lblEncryptPassPhrase = new JLabel("Pass Phrase:");
	private JCheckBox chckbxEncryptBase64 = new JCheckBox("Ouput as Base64");
	private JCheckBox chckbxEncryptOutputHex = new JCheckBox("Convert Output to Hex");
	private JPanel groupBoxEncryptASymetricPrivate = new JPanel();
	private JButton btnBrowseAsymKeyFile = new JButton("Browse");
	private JPanel certificateManagement = new JPanel();
	private JPanel keyGeneration = new JPanel();
	private JPanel hashAndMac = new JPanel();
	private JPanel signAndVerify = new JPanel();
	private JPanel groupBoxHashingParams = new JPanel();
	private JComboBox<String> comboHashFunctions = new JComboBox<String>();
	private JLabel lblHashFunction = new JLabel("Hash Function:");
	private JLabel lblEncryptHelp = new JLabel("Press \"F1\" key to start the Encryption and \"Esc\" to clear text areas");
	private JLabel lblEncyptStatus = new JLabel("Status: ");
	private JLabel lblEncryptStatusBox = new JLabel("Idle");
	private JTextField txtHashInputFile;
	private JTextArea textAreaHashInput = new JTextArea();
	private JPanel groupBoxHashText = new JPanel();
	private JTextArea textAreaHashOutput = new JTextArea();
	private JLabel lblPressescKey = new JLabel("Press \"F1\" key to start the Hashing and \"Esc\" key to clear text areas");
	private JButton btnBrowseHashInput = new JButton("Browse");
	private JButton btnStartFileHashing = new JButton("Start File  Hashing");
	private JLabel lblHashStatusBox = new JLabel("Idle");
	private JLabel lblHashStatus = new JLabel("Status: ");
	private JButton btnSwapFilesEncDec = new JButton("Swap Files");
	private JComboBox<String> comboSymetricAsymetric = new JComboBox<String>();
	private JTextField txtKeyGenRSAKeyFile;
	private JPasswordField passwordFieldKeyGenPassPhrase;
	private JComboBox<String> comboKeyGenPublicKeyFileFormatRSA = new JComboBox<String>();
	private JLabel lblKeyGenPublicKeyFileFormatRSA = new JLabel("Public Key File Format:");
	private JPanel groupBoxKeyGenRSAParams = new JPanel();
	private JLabel lblKeyGenRsaExplanation = new JLabel("Public Key file with selected Output format to be generated under selected folder");
	private JPanel groupBoxKeyGenECC = new JPanel();
	private JTextField txtKeyGenECCKeyFile = new JTextField();
	private JButton btnBrowseKeyGenECCKeyFile = new JButton("Browse");
	private JButton btnStartKeyGenECC = new JButton("Start Eliptic Curve Key Generation");
	private JLabel lblKeygenStatusECC = new JLabel("Status: ");
	private JLabel lblKeygenStatusDescECC = new JLabel("Idle");
	private JComboBox<String> comboKeyGenPublicKeyFileFormatECC = new JComboBox<String>();
	private JLabel lblKeyGenPublicKeyFileFormatECC = new JLabel("Public Key File Format:");
	private JPanel groupBoxKeyGenECName = new JPanel();
	private JLabel lblKeyGenElipticCurveName = new JLabel("Eliptic Curve Name:");
	private JComboBox<String> comboKeyGenElipticCurveName = new JComboBox<String>();
	private JLabel lblKeyGenECCExplanation = new JLabel("Public Key file with selected Output format to be generated under selected folder");
	private JTextArea txtKeyGenHumanReadable = new JTextArea();
	private JPanel groupBoxKeyGenRSA = new JPanel();
	private JButton btnBrowseKeyGenRSAKeyFile = new JButton("Browse");
	private JButton btnStartKeyGenRSA = new JButton("Start RSA Key Generation");
	private JLabel lblKeygenStatusRSA = new JLabel("Status: ");
	private JLabel lblKeygenStatusDescRSA = new JLabel("Idle");
	private JComboBox<String> comboKeyGenRsaKeyLength = new JComboBox<String>();
	private JLabel lblKeyGenRsaKeyLength = new JLabel("RSA Key Length:");
	private JCheckBox chckbxKeyGenEncrypt = new JCheckBox("Encrypt Key");
	private JLabel lblKeyGenCipher = new JLabel("Cipher:");
	private JComboBox<String> comboKeyGenCipher = new JComboBox<String>();
	private JLabel lblKeyGenPassPhrase = new JLabel("Pass Phrase:");
	private JTextField txtSignVerifyVerifyInputFile;
	private JTextField txtSignVerifyVerifyPubKeyFile;
	private JTextField txtSignVerifySignInputFile;
	private JTextField txtSignVerifySignPrivKeyFile;
	private JCheckBox chckbxEncryptDecryptRSAOaep = new JCheckBox("Enable RSA Oaep");
	private JLabel lblEncryptDecryptHashFunction = new JLabel("Hash Function:");
	private JComboBox<String> comboEncryptDecryptHashFunctions = new JComboBox<String>();
	private JComboBox<String> comboSignVerifyHashingFunction = new JComboBox<String>();
	private JButton btnBrowseSignVerifySignInputFile = new JButton("Browse");
	private JComboBox<String> comboSignVerifyRSAPaddingMode = new JComboBox<String>();
	private JComboBox<String> comboSignVerifyRSASaltLength = new JComboBox<String>();
	private JButton btnStartVerify = new JButton("Start Verification");
	private JTextField txtSignVerifyToBeVerifiedAgainstFile;
	private JLabel lblKeyGenPublicKeyFileFormatRSA_1 = new JLabel("Private Key File Format:");
	private JComboBox<String> comboSignVerifySigningKeyFileFormat = new JComboBox<String>();
	private JLabel lblKeyGenPublicKeyFileFormatRSA_1_1 = new JLabel("Public Key File Format:");
	private JComboBox<String> comboSignVerifyVerifyKeyFileFormat = new JComboBox<String>();
	private JScrollPane scrollPane = new JScrollPane();
	private JScrollPane scrollPane_1 = new JScrollPane();
	private JScrollPane scrollPane_2 = new JScrollPane();
	private JScrollPane scrollPane_3 = new JScrollPane();
	private JScrollPane scrollPane_4 = new JScrollPane();
	private JCheckBox chckbxSignVerifyRSASignature = new JCheckBox("RSA Padding");
	private JComboBox<String> comboSignVerifyRSAMgf1 = new JComboBox<String>();
	private JLabel lblSignVerifyRSASaltLength = new JLabel("RSA Salt Length:");
	private JLabel lblSignVerifyRsaMgf1 = new JLabel("RSA Mgf1 Digest:");
	private JTextArea textAreaSignVerify = new JTextArea();
	private final JScrollPane scrollPane_5 = new JScrollPane();
	private JTextField txtCertSelectIntermediate;
	private JTextField txtCertSelectRoot;
	private JTextField txtCertSelectEndEntity;
	private JButton btnDisplayCertEndEntity = new JButton("View File");
	private JButton btnDisplayCertIntermediate = new JButton("View File");
	private JButton btnDisplayCertRoot = new JButton("View File");
	private JPanel groupBoxCertGenerate = new JPanel();
	private JButton btnGenerateCertificates = new JButton("Generate Certificates");
	private JTable tableCertAttributes;
	private JComboBox<String> comboBoxCertKeyMethodRoot = new JComboBox<String>() ;
	private JButton btnBrowseCertSelectRoot = new JButton("Browse");
	private JButton btnBrowseCertSelectIntermediate = new JButton("Browse");
	private JButton btnBrowseCertSelectEndEntity = new JButton("Browse");
	private JButton btnVerifyCertChain = new JButton("Verify Chanin of Certificates");
	private JTextArea textCertStatus = new JTextArea();
	private JComboBox<String> comboBoxCertKeyMethodIntermediate = new JComboBox<String>();
	private JComboBox<String> comboBoxCertKeyMethodEndEntity = new JComboBox<String>();
	private JCheckBox chckbxCertVerifyIgnoreIntermediate = new JCheckBox("Ignore Intermediate");
	private JTextArea textAreaOpenSslCmd = new JTextArea();
	private JComboBox<String> comboBoxCertHashFuncRoot = new JComboBox<String>();
	private JComboBox<String> comboBoxCertHashFuncIntermediate = new JComboBox<String>();
	private JComboBox<String> comboBoxCertHashFuncEndEntity = new JComboBox<String>();
	private JComboBox<String> comboEncryptCiphersCmac = new JComboBox<String>();
	
	private String subjAttribsCertStr[] = {"CN", "OU", "O", "L", "ST", "C", "T", "SERIALNUMBER", "GN", "SN", "initials", "pseudonym", "DC", "STREET", "UID", "dnQualifier", "generationQualifier"};
	private JTextField txtCertGenSelectPath;
	private final JScrollPane scrollPaneOpenSslCmd = new JScrollPane();
	private final JButton btnClearCmdTextArea = new JButton("Clear Open SSL Commands");
	private boolean certificateWsSelected = false;
	private boolean eccKeyGenPathSelected = false;
	private boolean rsaKeyGenPathSelected = false;
	private boolean hashMsgFileSelected = false;
	private boolean FCInputFileSelected = false;
	private String CertWSPath1BackSlash, CertWSPath2BackSlash, CertWSPath4BackSlash;
	private JPasswordField passwordFieldMac;
	private final ButtonGroup buttonGroupCRC = new ButtonGroup();
	private final ButtonGroup buttonGroupHash = new ButtonGroup();
	private final JScrollPane textAreaScrollPaneFC = new JScrollPane();
	private JTextField txtFCSelectInputFile;
	private final JComboBox<String> comboFCFileViewFormat = new JComboBox<String>();
	private final JButton btnFCConvertFile = new JButton("Apply Operation");
	private JRadioButton rdbtnHash;
	private JTextField textFieldPrimeNumOFBits;
	private JTextArea textPrimeNumber;
	private JButton btnGeneratePrime;
	private JCheckBox chckboxPrimeHexOutput;
	private JCheckBox chckboxSafePrime;
	private final JRadioButton rdbtnCRC64 = new JRadioButton("CRC 64");
	private final JComboBox<String> comboCRCPredifened = new JComboBox<String>();
	private final JLabel lblPredefinedParameters = new JLabel("Predefined:");
	private JTextField textFieldCRCPolynomial = new JTextField();
	private final JTextArea textCRCOutput = new JTextArea();
	private final JLabel lblCRCInitValue = new JLabel("Init Value (Hex):");
	private final JTextField textFieldCRCInit = new JTextField();
	private final JLabel lblCRCXOR = new JLabel("XOR Value (Hex):");
	private final JTextField textFieldCRCXorValue = new JTextField();
	private JTextField textFieldCRCFileInput;
	private final JTextArea textCRCInput = new JTextArea(); 
	private final JRadioButton rdbtnCRC8 = new JRadioButton("CRC 8");
	private final JRadioButton rdbtnCRC16 = new JRadioButton("CRC 16");
	private final JRadioButton rdbtnCRC32 = new JRadioButton("CRC 32");
	private final JCheckBox chckbxCRCReflectResult  = new JCheckBox("Reflect Result");
	private final JCheckBox chckbxCRCReflectInput = new JCheckBox("Reflect Input");

	private boolean isCRCFileInputAssigned = false;
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainFrame frame = new MainFrame();
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
	public MainFrame() 
	{		
		setIconImage(Toolkit.getDefaultToolkit().getImage("C:\\ZGRRDNR\\PROJECTS\\FRIDAY_INNOVATION\\CryptoCalculatorTool\\src\\CryptoCalculator.PNG"));
		
		selfInstance = this;
				
		setResizable(false);
		setTitle("Crypto Calculator");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 901, 732);
		mainPane = new JPanel();
		mainPane.setAutoscrolls(true);
		mainPane.setBorder(new EmptyBorder(5, 5, 5, 5));

		setContentPane(mainPane);
		mainPane.setLayout(null);
		tabbedPane.setAutoscrolls(true);
		
		tabbedPane.setBounds(10, 11, 865, 544);
		mainPane.add(tabbedPane);
		
		comboKeyGenRsaKeyLength.addItem("1024-bit");
		comboKeyGenRsaKeyLength.addItem("2048-bit");
		comboKeyGenRsaKeyLength.addItem("4096-bit");
		
		comboSignVerifyRSAPaddingMode.addItemListener(new ItemListener() 
		{
			public void itemStateChanged(ItemEvent arg0) 
			{
				if(((String)comboSignVerifyRSAPaddingMode.getSelectedItem()).compareTo("pss") == 0)
				{
					comboSignVerifyRSASaltLength.setEnabled(true);
					lblSignVerifyRsaMgf1.setEnabled(true);
					comboSignVerifyRSAMgf1.setEnabled(true);
					lblSignVerifyRSASaltLength.setEnabled(true);
				}
				
				else
				{
					comboSignVerifyRSASaltLength.setEnabled(false);
					lblSignVerifyRsaMgf1.setEnabled(false);
					comboSignVerifyRSAMgf1.setEnabled(false);
					lblSignVerifyRSASaltLength.setEnabled(false);
				}
			}
		});
		
		comboSignVerifyRSAPaddingMode.setEnabled(false);
		
		comboSignVerifyRSAPaddingMode.addItem("pkcs1");
		comboSignVerifyRSAPaddingMode.addItem("pss");
		comboSignVerifyRSAPaddingMode.addItem("sslv23");
		comboSignVerifyRSAPaddingMode.addItem("x931");
		comboSignVerifyRSASaltLength.setEnabled(false);
		
		comboSignVerifyRSASaltLength.addItem("digest");
		comboSignVerifyRSASaltLength.addItem("auto");
		comboSignVerifyRSASaltLength.addItem("max");
		
		comboKeyGenPublicKeyFileFormatECC.addItem("PEM");
		comboKeyGenPublicKeyFileFormatECC.addItem("DER");
		
		comboKeyGenPublicKeyFileFormatRSA.addItem("PEM");
		comboKeyGenPublicKeyFileFormatRSA.addItem("DER");
		
		comboSignVerifySigningKeyFileFormat.addItem("PEM");
		comboSignVerifySigningKeyFileFormat.addItem("DER");
		
		comboSignVerifyVerifyKeyFileFormat.addItem("PEM");
		comboSignVerifyVerifyKeyFileFormat.addItem("DER");
		
		comboFCFileViewFormat.addItem("Select File Operation");
		comboFCFileViewFormat.addItem("View Certificate in Human Readable Form");
		comboFCFileViewFormat.addItem("View CRL in Human Readable Form");
		comboFCFileViewFormat.addItem("View RSA Private Key in Human Readable Form");
		comboFCFileViewFormat.addItem("View RSA Public Key in Human Readable Form");
		comboFCFileViewFormat.addItem("View ECC Private Key in Human Readable Form");
		comboFCFileViewFormat.addItem("View ECC Public Key in Human Readable Form");
		comboFCFileViewFormat.addItem("Convert PEM Certificate to DER");
		comboFCFileViewFormat.addItem("Convert DER Certificate to PEM");
		comboFCFileViewFormat.addItem("Convert PEM CRL to DER");
		comboFCFileViewFormat.addItem("Convert DER CRL to PEM");
		comboFCFileViewFormat.addItem("Convert PEM RSA Private Key to DER");
		comboFCFileViewFormat.addItem("Convert DER RSA Private Key to PEM");
		comboFCFileViewFormat.addItem("Convert PEM RSA Public Key to DER");
		comboFCFileViewFormat.addItem("Convert DER RSA Public Key to PEM");
		comboFCFileViewFormat.addItem("Convert PEM ECC Private Key to DER");
		comboFCFileViewFormat.addItem("Convert DER ECC Private Key to PEM");
		comboFCFileViewFormat.addItem("Convert PEM ECC Public Key to DER");
		comboFCFileViewFormat.addItem("Convert DER ECC Public Key to PEM");
		comboFCFileViewFormat.addItem("Convert Text File to Base64 File");
		comboFCFileViewFormat.addItem("Convert Base64 File to Text File");
		comboFCFileViewFormat.addItem("ASN.1 Parse PEM File");
		comboFCFileViewFormat.addItem("ASN.1 Parse DER File");
		
		tabbedPane.addTab("Key Operations", null, keyGeneration, null);
		keyGeneration.setLayout(null);
		
		groupBoxKeyGenRSA.setLayout(null);
		groupBoxKeyGenRSA.setToolTipText("Output of Encryption");
		groupBoxKeyGenRSA.setName("");
		groupBoxKeyGenRSA.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxKeyGenRSA.setBounds(10, 11, 840, 170);
		keyGeneration.add(groupBoxKeyGenRSA);
		
		txtKeyGenRSAKeyFile = new JTextField();
		txtKeyGenRSAKeyFile.setText("Select Path to Store Generated Key Files");
		txtKeyGenRSAKeyFile.setEditable(false);
		txtKeyGenRSAKeyFile.setColumns(10);
		txtKeyGenRSAKeyFile.setBounds(10, 82, 721, 20);
		groupBoxKeyGenRSA.add(txtKeyGenRSAKeyFile);
		
		btnBrowseKeyGenRSAKeyFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtKeyGenRSAKeyFile.setText(fileChooser.getSelectedFile().getPath());
					
					lblKeygenStatusDescRSA.setText("Private Key File selected");
					
					rsaKeyGenPathSelected = true;
				}
			
			}
		});
		
		btnBrowseKeyGenRSAKeyFile.setBounds(741, 81, 89, 23);
		groupBoxKeyGenRSA.add(btnBrowseKeyGenRSAKeyFile);
		textAreaOpenSslCmd.setEditable(false);
		
		scrollPaneOpenSslCmd.setViewportView(textAreaOpenSslCmd);
		
		btnStartKeyGenRSA.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(rsaKeyGenPathSelected == false)
				{
					lblKeygenStatusDescRSA.setText("!!! Select the path which private and public key files to be generated !!!");
					return;
				}
				
				String prvKeyFile = "\"" + txtKeyGenRSAKeyFile.getText() + "\\privkey_" + (String)comboKeyGenRsaKeyLength.getSelectedItem() + "_rsa.key\"";
				String pubKeyFile = "\"" + txtKeyGenRSAKeyFile.getText() + "\\pubkey_" + (String)comboKeyGenRsaKeyLength.getSelectedItem() + "_rsa." + ((String)comboKeyGenPublicKeyFileFormatRSA.getSelectedItem()).toLowerCase() + "\"";
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("genrsa");
				
				if(chckbxKeyGenEncrypt.isSelected() == true)	
				{
					cmdInterpretor.addCommandLineStr(((String)comboKeyGenCipher.getSelectedItem()).replaceAll(" ", ""));
					cmdInterpretor.addCommandLineStr("-passout");
					cmdInterpretor.addCommandLineStr("pass::" + new String(passwordFieldKeyGenPassPhrase.getPassword()));
				}
				
				cmdInterpretor.addCommandLineStr("-out");
				cmdInterpretor.addCommandLineStr(prvKeyFile);
				
				if(((String)comboKeyGenRsaKeyLength.getSelectedItem()).compareTo("1024-bit") == 0)	
				{
					cmdInterpretor.addCommandLineStr("1024");
				}
				
				if(((String)comboKeyGenRsaKeyLength.getSelectedItem()).compareTo("2048-bit") == 0)	
				{
					cmdInterpretor.addCommandLineStr("2048");
				}
				
				if(((String)comboKeyGenRsaKeyLength.getSelectedItem()).compareTo("4096-bit") == 0)	
				{
					cmdInterpretor.addCommandLineStr("4096");
				}
				
				String cmdRetStr = cmdInterpretor.runCommand();
								
				if(cmdRetStr.compareTo("") != 0)
				{
					lblKeygenStatusDescRSA.setText(cmdRetStr);
				}
				else
				{
					lblKeygenStatusDescRSA.setText("Private Key File Completed");
				}
				
				displayCmdInTextAreaAndClear();
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("rsa");
				cmdInterpretor.addCommandLineStr("-pubout");
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(prvKeyFile);
				
				if(chckbxKeyGenEncrypt.isSelected() == true)	
				{
					cmdInterpretor.addCommandLineStr("-passin");
					cmdInterpretor.addCommandLineStr("pass::" + (String)(new String(passwordFieldKeyGenPassPhrase.getPassword())));
				}
				
				cmdInterpretor.addCommandLineStr("-outform");
				cmdInterpretor.addCommandLineStr((String)comboKeyGenPublicKeyFileFormatRSA.getSelectedItem());
				cmdInterpretor.addCommandLineStr("-out");
				cmdInterpretor.addCommandLineStr(pubKeyFile);

				cmdInterpretor.runCommand();
												
				displayCmdInTextAreaAndClear();
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("rsa");
				
				if(chckbxKeyGenEncrypt.isSelected() == true)	
				{
					cmdInterpretor.addCommandLineStr("-passin");
					cmdInterpretor.addCommandLineStr("pass::" + (String)(new String(passwordFieldKeyGenPassPhrase.getPassword())));
				}
				
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(prvKeyFile);
				cmdInterpretor.addCommandLineStr("-noout");
				cmdInterpretor.addCommandLineStr("-text");
					  
				txtKeyGenHumanReadable.setText(cmdInterpretor.runCommand());
				
				displayCmdInTextAreaAndClear();
				
				String[] prvKeyFileNameParsed = prvKeyFile.split("\\\\");
				String[] pubKeyFileNameParsed = pubKeyFile.split("\\\\");
				
				lblKeygenStatusDescRSA.setText( "\"" + prvKeyFileNameParsed[prvKeyFileNameParsed.length - 1] + " and " + "\"" + pubKeyFileNameParsed[pubKeyFileNameParsed.length - 1] +  " Files generated in selected folder");
			}
		});
		
		btnStartKeyGenRSA.setBounds(315, 113, 184, 20);
		groupBoxKeyGenRSA.add(btnStartKeyGenRSA);
		
		lblKeygenStatusRSA.setBounds(10, 145, 46, 14);
		groupBoxKeyGenRSA.add(lblKeygenStatusRSA);
		
		lblKeygenStatusDescRSA.setBounds(58, 145, 772, 14);
		groupBoxKeyGenRSA.add(lblKeygenStatusDescRSA);
		comboKeyGenPublicKeyFileFormatRSA.setBounds(741, 113, 89, 22);
		
		groupBoxKeyGenRSA.add(comboKeyGenPublicKeyFileFormatRSA);
		lblKeyGenPublicKeyFileFormatRSA.setBounds(609, 116, 132, 14);
		
		groupBoxKeyGenRSA.add(lblKeyGenPublicKeyFileFormatRSA);
		groupBoxKeyGenRSAParams.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxKeyGenRSAParams.setBounds(10, 11, 820, 41);
		
		groupBoxKeyGenRSA.add(groupBoxKeyGenRSAParams);
		groupBoxKeyGenRSAParams.setLayout(null);
		
		chckbxKeyGenEncrypt.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(chckbxKeyGenEncrypt.isSelected() == true)
				{
					comboKeyGenCipher.setEnabled(true);
					passwordFieldKeyGenPassPhrase.setEnabled(true);
					lblKeyGenCipher.setEnabled(true);
					lblKeyGenPassPhrase.setEnabled(true);
				}
				
				if(chckbxKeyGenEncrypt.isSelected() == false)
				{
					comboKeyGenCipher.setEnabled(false);
					passwordFieldKeyGenPassPhrase.setEnabled(false);
					lblKeyGenCipher.setEnabled(false);
					lblKeyGenPassPhrase.setEnabled(false);
				}
			}
		});
		
		chckbxKeyGenEncrypt.setBounds(227, 11, 92, 23);
		groupBoxKeyGenRSAParams.add(chckbxKeyGenEncrypt);
		lblKeyGenCipher.setEnabled(false);
		
		lblKeyGenCipher.setBounds(325, 15, 66, 14);
		groupBoxKeyGenRSAParams.add(lblKeyGenCipher);
		comboKeyGenCipher.setEnabled(false);
		
		comboKeyGenCipher.setBounds(390, 11, 153, 22);
		groupBoxKeyGenRSAParams.add(comboKeyGenCipher);
		lblKeyGenPassPhrase.setEnabled(false);
		
		lblKeyGenPassPhrase.setBounds(557, 13, 92, 14);
		groupBoxKeyGenRSAParams.add(lblKeyGenPassPhrase);
		
		passwordFieldKeyGenPassPhrase = new JPasswordField();
		passwordFieldKeyGenPassPhrase.setEnabled(false);
		passwordFieldKeyGenPassPhrase.setBounds(656, 11, 154, 20);
		groupBoxKeyGenRSAParams.add(passwordFieldKeyGenPassPhrase);
		passwordFieldKeyGenPassPhrase.setText("1234567890");
		
		lblKeyGenRsaKeyLength.setBounds(10, 15, 99, 14);
		groupBoxKeyGenRSAParams.add(lblKeyGenRsaKeyLength);
		
				comboKeyGenRsaKeyLength.setBounds(111, 11, 92, 22);
				groupBoxKeyGenRSAParams.add(comboKeyGenRsaKeyLength);
				lblKeyGenRsaExplanation.setBounds(10, 63, 721, 14);
				
				groupBoxKeyGenRSA.add(lblKeyGenRsaExplanation);
				groupBoxKeyGenECC.setLayout(null);
				groupBoxKeyGenECC.setToolTipText("Output of Encryption");
				groupBoxKeyGenECC.setName("");
				groupBoxKeyGenECC.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
				groupBoxKeyGenECC.setBounds(10, 335, 840, 170);
				
				keyGeneration.add(groupBoxKeyGenECC);
				txtKeyGenECCKeyFile.setText("Select Path to Store Generated Key Files");
				txtKeyGenECCKeyFile.setEditable(false);
				txtKeyGenECCKeyFile.setColumns(10);
				txtKeyGenECCKeyFile.setBounds(10, 82, 721, 20);
				
				groupBoxKeyGenECC.add(txtKeyGenECCKeyFile);
				
				btnBrowseKeyGenECCKeyFile.addMouseListener(new MouseAdapter() 
				{
					@Override
					public void mouseClicked(MouseEvent arg0) 
					{
						JFileChooser fileChooser = new JFileChooser();
						
						fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
						
						if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
						{
							txtKeyGenECCKeyFile.setText(fileChooser.getSelectedFile().getPath());
							
							lblKeygenStatusDescECC.setText("Private Key File selected");
							
							eccKeyGenPathSelected = true;
						}
					}
				});
				
				btnBrowseKeyGenECCKeyFile.setBounds(741, 81, 89, 23);
				
				groupBoxKeyGenECC.add(btnBrowseKeyGenECCKeyFile);
				
				btnStartKeyGenECC.addMouseListener(new MouseAdapter() 
				{
					@Override
					public void mouseClicked(MouseEvent arg0) 
					{
						if(eccKeyGenPathSelected == false)
						{
							lblKeygenStatusDescECC.setText("!!! Select the path which private and public key files to be generated !!!");
							return;
						}
						
						String prvKeyFile = "\"" + txtKeyGenECCKeyFile.getText() + "\\privkey_" + (String)comboKeyGenElipticCurveName.getSelectedItem() + "_ec.key\"";
						String pubKeyFile = "\"" + txtKeyGenECCKeyFile.getText() + "\\pubkey_" + (String)comboKeyGenElipticCurveName.getSelectedItem() + "_ec." + ((String)comboKeyGenPublicKeyFileFormatECC.getSelectedItem()).toLowerCase() + "\"";
						
						cmdInterpretor.addCommandLineStr("openssl"); 
						cmdInterpretor.addCommandLineStr("ecparam");
						cmdInterpretor.addCommandLineStr("-genkey");
						cmdInterpretor.addCommandLineStr("-name");
						cmdInterpretor.addCommandLineStr((String)comboKeyGenElipticCurveName.getSelectedItem());
						cmdInterpretor.addCommandLineStr("-out");
						cmdInterpretor.addCommandLineStr(prvKeyFile);
						
						lblKeygenStatusDescECC.setText("Key Generation In Progress ...");
										
						String cmdRetStr = cmdInterpretor.runCommand();
										
						if(cmdRetStr.compareTo("") != 0)
						{
							lblKeygenStatusDescECC.setText(cmdRetStr);
						}
						else
						{
							lblKeygenStatusDescECC.setText("Private Key File Completed");
						}
						
						displayCmdInTextAreaAndClear();
						
						cmdInterpretor.addCommandLineStr("openssl"); 
						cmdInterpretor.addCommandLineStr("ec");
						cmdInterpretor.addCommandLineStr("-pubout");
						cmdInterpretor.addCommandLineStr("-in");
						cmdInterpretor.addCommandLineStr(prvKeyFile);
						cmdInterpretor.addCommandLineStr("-out");
						cmdInterpretor.addCommandLineStr(pubKeyFile);
						cmdInterpretor.addCommandLineStr("-outform");
						cmdInterpretor.addCommandLineStr((String)comboKeyGenPublicKeyFileFormatECC.getSelectedItem());

						txtKeyGenHumanReadable.setText(cmdInterpretor.runCommand());
														
						displayCmdInTextAreaAndClear();
						
						cmdInterpretor.addCommandLineStr("openssl"); 
						cmdInterpretor.addCommandLineStr("ec");
						cmdInterpretor.addCommandLineStr("-in");
						cmdInterpretor.addCommandLineStr(prvKeyFile);
						cmdInterpretor.addCommandLineStr("-noout");
						cmdInterpretor.addCommandLineStr("-text");
							  
						txtKeyGenHumanReadable.setText(cmdInterpretor.runCommand());
										
						displayCmdInTextAreaAndClear();
						
						String[] prvKeyFileNameParsed = prvKeyFile.split("\\\\");
						String[] pubKeyFileNameParsed = pubKeyFile.split("\\\\");
						
						lblKeygenStatusDescECC.setText( "\"" + prvKeyFileNameParsed[prvKeyFileNameParsed.length - 1] + " and " + "\"" + pubKeyFileNameParsed[pubKeyFileNameParsed.length - 1] +  " Files generated  in selected folder");
					}
				});
				
				btnStartKeyGenECC.setBounds(311, 113, 247, 20);
				
				groupBoxKeyGenECC.add(btnStartKeyGenECC);
				lblKeygenStatusECC.setBounds(10, 145, 46, 14);
				
				groupBoxKeyGenECC.add(lblKeygenStatusECC);
				lblKeygenStatusDescECC.setBounds(58, 145, 772, 14);
				
				groupBoxKeyGenECC.add(lblKeygenStatusDescECC);
				comboKeyGenPublicKeyFileFormatECC.setBounds(741, 113, 89, 22);
				
				groupBoxKeyGenECC.add(comboKeyGenPublicKeyFileFormatECC);
				lblKeyGenPublicKeyFileFormatECC.setBounds(609, 116, 132, 14);
				
				groupBoxKeyGenECC.add(lblKeyGenPublicKeyFileFormatECC);
				groupBoxKeyGenECName.setLayout(null);
				groupBoxKeyGenECName.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
				groupBoxKeyGenECName.setBounds(10, 11, 820, 41);
				
				groupBoxKeyGenECC.add(groupBoxKeyGenECName);
				lblKeyGenElipticCurveName.setBounds(10, 15, 111, 14);
				
				groupBoxKeyGenECName.add(lblKeyGenElipticCurveName);
				comboKeyGenElipticCurveName.setBounds(131, 11, 172, 22);
				
				groupBoxKeyGenECName.add(comboKeyGenElipticCurveName);
				lblKeyGenECCExplanation.setBounds(10, 63, 820, 14);
				
				groupBoxKeyGenECC.add(lblKeyGenECCExplanation);
				scrollPane.setBounds(10, 192, 840, 132);
				
				keyGeneration.add(scrollPane);
				scrollPane.setViewportView(txtKeyGenHumanReadable);
				
				txtKeyGenHumanReadable.setText("Human Readable Generated Key File to be displayed here ");
				txtKeyGenHumanReadable.setEditable(false);
				
		encrypt.setAutoscrolls(true);
		
		tabbedPane.addTab("Encrypt & Decrypt", null, encrypt, null);
		tabbedPane.setEnabledAt(1, true);
		encrypt.setLayout(null);
		groupBoxEncryptText.setAutoscrolls(true);
		
		groupBoxEncryptText.setToolTipText("Input for Encryption");
		groupBoxEncryptText.setName("");
		groupBoxEncryptText.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxEncryptText.setBounds(10, 143, 840, 226);
		encrypt.add(groupBoxEncryptText);
		groupBoxEncryptText.setLayout(null);
		
		comboSymetricAsymetric.addItemListener(new ItemListener() 
		{
			public void itemStateChanged(ItemEvent arg0) 
			{
				if(comboSymetricAsymetric.getSelectedIndex()== COMBO_INDEX_SYMETRIC_CRYPTO_ENCRYPT || comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_SYMETRIC_CRYPTO_DECRYPT)
				{
					txtAsymetricKeyFile.setEnabled(false);
					btnBrowseAsymKeyFile.setEnabled(false);

					chckbxEncryptDecryptRSAOaep.setEnabled(false);
					lblEncryptDecryptHashFunction.setEnabled(false);
					comboEncryptDecryptHashFunctions.setEnabled(false);
					
					chckbxEncryptDecryptRSAOaep.setSelected(false);
					
					comboEncryptCiphers.setEnabled(true);
					pwdEncryptAddPassPhrase.setEnabled(true);
					chckbxEncryptAddSalt.setEnabled(true);
					chckbxEncryptBase64.setEnabled(true);
					lblEncryptAlgorithm.setEnabled(true);
					lblEncryptPassPhrase.setEnabled(true);
					
					txtAsymetricKeyFile.setText("Symetric key Crypto Selected this is Not Applicable");
				}
				
				if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_ENCRYPT || comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_DECRYPT)
				{
					txtAsymetricKeyFile.setEnabled(true);
					btnBrowseAsymKeyFile.setEnabled(true);
					
					chckbxEncryptDecryptRSAOaep.setEnabled(true);
					lblEncryptDecryptHashFunction.setEnabled(false);
					comboEncryptDecryptHashFunctions.setEnabled(false);
					
					if(chckbxEncryptDecryptRSAOaep.isSelected() == true)
					{
						lblEncryptDecryptHashFunction.setEnabled(true);
						comboEncryptDecryptHashFunctions.setEnabled(true);
					}
					
					comboEncryptCiphers.setEnabled(false);
					pwdEncryptAddPassPhrase.setEnabled(false);
					chckbxEncryptAddSalt.setEnabled(false);
					chckbxEncryptBase64.setEnabled(false);
					lblEncryptAlgorithm.setEnabled(false);
					lblEncryptPassPhrase.setEnabled(false);
					
					if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_ENCRYPT)
					{
						txtAsymetricKeyFile.setText("Select Public key File for Asymetric Encryption");
					}
					
					if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_DECRYPT)
					{
						txtAsymetricKeyFile.setText("Select Private key File for Asymetric Decryption");
					}
				}
				
				if(comboSymetricAsymetric.getSelectedIndex()== COMBO_INDEX_SYMETRIC_CRYPTO_ENCRYPT || comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_ENCRYPT)
				{
					textAreaEncryptInput.setEnabled(true);
					textAreaEncryptOutput.setEnabled(true);
					chckbxEncryptOutputHex.setEnabled(true);
					lblEncryptHelp.setEnabled(true);
					
					btnStartFileEncrypt.setText("Start File  Encryption");
					txtEncryptDecryptFileInput.setText("Select Input File to be Encrypted");
					txtEncryptDecryptFileOutput.setText("Select Output File to be Written");
				}
				
				if(comboSymetricAsymetric.getSelectedIndex()== COMBO_INDEX_SYMETRIC_CRYPTO_DECRYPT || comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_DECRYPT)
				{
					textAreaEncryptInput.setEnabled(false);
					textAreaEncryptOutput.setEnabled(false);
					chckbxEncryptOutputHex.setEnabled(false);
					lblEncryptHelp.setEnabled(false);
					
					btnStartFileEncrypt.setText("Start File  Decryption");
					txtEncryptDecryptFileInput.setText("Select Input File to be Decrypted");
					txtEncryptDecryptFileOutput.setText("Select Output File to be Written");
				}
			}
		});
		
		comboSymetricAsymetric.addItem("Symetric Key Encryption");
		comboSymetricAsymetric.addItem("Symetric Key Decryption");
		comboSymetricAsymetric.addItem("Asymetric (Public) Key Encryption");
		comboSymetricAsymetric.addItem("Asymetric (Public) Key Decryption");
		scrollPane_1.setBounds(10, 11, 820, 79);
		
		groupBoxEncryptText.add(scrollPane_1);
		scrollPane_1.setViewportView(textAreaEncryptInput);
		
		textAreaEncryptInput.addKeyListener(new KeyAdapter() 
		{
			@Override
			public void keyPressed(KeyEvent arg0) 
			{
				if(arg0.getKeyCode() == 112)
				{
					File tmpFile = new File("tmp.txt");
					
					try 
					{
						tmpFile.createNewFile();
						
						FileWriter tmpFileWriter = new FileWriter(tmpFile);
						tmpFileWriter.write(textAreaEncryptInput.getText());
						tmpFileWriter.close();
					} 
					catch (IOException e) 
					{
						e.printStackTrace();
					}
					
					if(comboSymetricAsymetric.getSelectedIndex() == 0 )
					{
						cmdInterpretor.addCommandLineStr("openssl"); 
						cmdInterpretor.addCommandLineStr("enc");
						cmdInterpretor.addCommandLineStr((String)comboEncryptCiphers.getSelectedItem());
						cmdInterpretor.addCommandLineStr("-e");
						cmdInterpretor.addCommandLineStr("-in");
						cmdInterpretor.addCommandLineStr("tmp.txt");
						cmdInterpretor.addCommandLineStr("-k");
						cmdInterpretor.addCommandLineStr(new String(pwdEncryptAddPassPhrase.getPassword()));
						cmdInterpretor.addCommandLineStr("-pbkdf2");
						
						if(chckbxEncryptAddSalt.isSelected() == false)
						{
							cmdInterpretor.addCommandLineStr("-nosalt");
						}
						
						if(chckbxEncryptBase64.isSelected())
						{
							cmdInterpretor.addCommandLineStr("-a");
						}
					}
					
					if(comboSymetricAsymetric.getSelectedIndex() == 2)
					{
						cmdInterpretor.addCommandLineStr("openssl"); 
						cmdInterpretor.addCommandLineStr("rsautl");
						cmdInterpretor.addCommandLineStr("-in");
						cmdInterpretor.addCommandLineStr("tmp.txt");
						cmdInterpretor.addCommandLineStr("-pubin");
						cmdInterpretor.addCommandLineStr("-inkey");
						cmdInterpretor.addCommandLineStr("\"" + txtAsymetricKeyFile.getText() + "\"");
						cmdInterpretor.addCommandLineStr("-encrypt");
					}
														
					String cmdOutputStr = cmdInterpretor.runCommand();
					
					if(chckbxEncryptOutputHex.isSelected())
					{
						StringBuilder hexString = new StringBuilder();
						
						for (char c : cmdOutputStr.toCharArray()) 
						{
						  hexString.append("0x" + Integer.toHexString((int) c) + " ");
						}
						
						cmdOutputStr = hexString.toString();
					}
					
					textAreaEncryptOutput.setText(cmdOutputStr);
					displayCmdInTextAreaAndClear();
					
					tmpFile.delete();
				}
				
				if(arg0.getKeyCode() == 27)
				{
					textAreaEncryptInput.setText(null);
				}
			}
		});
		
		textAreaEncryptInput.setText("Click to Add or Copy Input Text to be Encrypted");
		scrollPane_2.setBounds(10, 130, 820, 85);
		
		groupBoxEncryptText.add(scrollPane_2);
		scrollPane_2.setViewportView(textAreaEncryptOutput);
		
		textAreaEncryptOutput.addKeyListener(new KeyAdapter() 
		{
			@Override
			public void keyPressed(KeyEvent arg0) 
			{
				if(arg0.getKeyCode() == 27)
				{
					textAreaEncryptOutput.setText(null);
				}
			}
		});
		textAreaEncryptOutput.setText("Encrypted Text will be displayed here");
		
		chckbxEncryptOutputHex.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(chckbxEncryptOutputHex.isEnabled() == false)
				{
					return;
				}
				
				if(chckbxEncryptOutputHex.isSelected())
				{
					previousTextAreaEncryptOutput = textAreaEncryptOutput.getText();
							
					String outputStr = textAreaEncryptOutput.getText();
					
					StringBuilder hexString = new StringBuilder();
					
					for (char c : outputStr.toCharArray()) 
					{
					  hexString.append("0x" + Integer.toHexString((int) c) + " ");
					}
					
					outputStr = hexString.toString();
					
					textAreaEncryptOutput.setText(outputStr);
					
					return;
				}
				
				textAreaEncryptOutput.setText(previousTextAreaEncryptOutput);
			}
		});
		
		chckbxEncryptOutputHex.setBounds(10, 97, 153, 23);
		groupBoxEncryptText.add(chckbxEncryptOutputHex);
		lblEncryptHelp.setFont(new Font("Tahoma", Font.BOLD, 12));
		lblEncryptHelp.setBounds(227, 100, 470, 14);
		
		groupBoxEncryptText.add(lblEncryptHelp);
		
		groupBoxEncryptFiles.setToolTipText("Output of Encryption");
		groupBoxEncryptFiles.setLayout(null);
		groupBoxEncryptFiles.setName("");
		groupBoxEncryptFiles.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxEncryptFiles.setBounds(10, 380, 840, 129);
		encrypt.add(groupBoxEncryptFiles);
		txtEncryptDecryptFileOutput.setEditable(false);
		
		txtEncryptDecryptFileOutput.setText("Select Encrypted Output File");
		txtEncryptDecryptFileOutput.setColumns(10);
		txtEncryptDecryptFileOutput.setBounds(10, 47, 721, 20);
		groupBoxEncryptFiles.add(txtEncryptDecryptFileOutput);
		txtEncryptDecryptFileInput.setEditable(false);
		
		txtEncryptDecryptFileInput.setBounds(10, 15, 721, 20);
		groupBoxEncryptFiles.add(txtEncryptDecryptFileInput);
		txtEncryptDecryptFileInput.setText("Select Input File to be encrypted");
		
		btnBrowseEncrptyDecryptInput.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtEncryptDecryptFileInput.setText(fileChooser.getSelectedFile().getPath());
										
					lblEncryptStatusBox.setText("Input File selected");
				}
			}
		});
		
		btnBrowseEncrptyDecryptOutput.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtEncryptDecryptFileOutput.setText(fileChooser.getSelectedFile().getPath());
										
					lblEncryptStatusBox.setText("Output File selected");
				}				
			}
		});
		
		txtEncryptDecryptFileInput.setColumns(10);
		
		btnBrowseEncrptyDecryptInput.setBounds(741, 14, 89, 23);
		groupBoxEncryptFiles.add(btnBrowseEncrptyDecryptInput);
		
		btnBrowseEncrptyDecryptOutput.setBounds(741, 46, 89, 23);
		groupBoxEncryptFiles.add(btnBrowseEncrptyDecryptOutput);
		
		btnStartFileEncrypt.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_SYMETRIC_CRYPTO_ENCRYPT)
				{
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("enc");
					cmdInterpretor.addCommandLineStr((String)comboEncryptCiphers.getSelectedItem());
					cmdInterpretor.addCommandLineStr("-e");
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileInput.getText() + "\"");
					cmdInterpretor.addCommandLineStr("-out");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileOutput.getText() + "\"");
					cmdInterpretor.addCommandLineStr("-k");
					cmdInterpretor.addCommandLineStr(new String(pwdEncryptAddPassPhrase.getPassword()));
					cmdInterpretor.addCommandLineStr("-pbkdf2");
					
					if(chckbxEncryptAddSalt.isSelected() == false)
					{
						cmdInterpretor.addCommandLineStr("-nosalt");
					}
					
					if(chckbxEncryptBase64.isSelected())
					{
						cmdInterpretor.addCommandLineStr("-a");
					}
					
					lblEncryptStatusBox.setText("Encryption In Progress ...");
				}
				
				if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_SYMETRIC_CRYPTO_DECRYPT)
				{
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("enc");
					cmdInterpretor.addCommandLineStr((String)comboEncryptCiphers.getSelectedItem());
					cmdInterpretor.addCommandLineStr("-d");
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileInput.getText() + "\"");
					cmdInterpretor.addCommandLineStr("-out");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileOutput.getText() + "\"");
					cmdInterpretor.addCommandLineStr("-k");
					cmdInterpretor.addCommandLineStr(new String(pwdEncryptAddPassPhrase.getPassword()));
					cmdInterpretor.addCommandLineStr("-pbkdf2");
					
					if(chckbxEncryptAddSalt.isSelected() == false)
					{
						cmdInterpretor.addCommandLineStr("-nosalt");
					}
					
					if(chckbxEncryptBase64.isSelected())
					{
						cmdInterpretor.addCommandLineStr("-a");
					}
					
					lblEncryptStatusBox.setText("Decryption In Progress ...");
				}
				
				if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_ENCRYPT)
				{
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("pkeyutl");
					cmdInterpretor.addCommandLineStr("-encrypt");
					cmdInterpretor.addCommandLineStr("-pubin");
					cmdInterpretor.addCommandLineStr("-inkey");
					cmdInterpretor.addCommandLineStr("\"" + txtAsymetricKeyFile.getText() + "\"");
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileInput.getText() + "\"");
					
					if(chckbxEncryptDecryptRSAOaep.isSelected() == true)
					{
						cmdInterpretor.addCommandLineStr("-pkeyopt"); 
						cmdInterpretor.addCommandLineStr("rsa_padding_mode:oaep");
						cmdInterpretor.addCommandLineStr("-pkeyopt");
						cmdInterpretor.addCommandLineStr("rsa_oaep_md:" + ((String)comboEncryptDecryptHashFunctions.getSelectedItem()).replaceAll("-", ""));
						cmdInterpretor.addCommandLineStr("-pkeyopt");
						cmdInterpretor.addCommandLineStr("rsa_mgf1_md:" + ((String)comboEncryptDecryptHashFunctions.getSelectedItem()).replaceAll("-", ""));
					}
					
					cmdInterpretor.addCommandLineStr("-out");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileOutput.getText() + "\"");
					
					lblEncryptStatusBox.setText("Encryption In Progress ...");
				}
				

				if(comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_DECRYPT)
				{
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("pkeyutl");
					cmdInterpretor.addCommandLineStr("-decrypt");
					cmdInterpretor.addCommandLineStr("-inkey");
					cmdInterpretor.addCommandLineStr("\"" + txtAsymetricKeyFile.getText() + "\"");
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileInput.getText() + "\"");
					
					if(chckbxEncryptDecryptRSAOaep.isSelected() == true)
					{
						cmdInterpretor.addCommandLineStr("-pkeyopt"); 
						cmdInterpretor.addCommandLineStr("rsa_padding_mode:oaep");
						cmdInterpretor.addCommandLineStr("-pkeyopt");
						cmdInterpretor.addCommandLineStr("rsa_oaep_md:" + ((String)comboEncryptDecryptHashFunctions.getSelectedItem()).replaceAll("-", ""));
						cmdInterpretor.addCommandLineStr("-pkeyopt");
						cmdInterpretor.addCommandLineStr("rsa_mgf1_md:" + ((String)comboEncryptDecryptHashFunctions.getSelectedItem()).replaceAll("-", ""));
					}
					
					cmdInterpretor.addCommandLineStr("-out");
					cmdInterpretor.addCommandLineStr("\"" + txtEncryptDecryptFileOutput.getText() + "\"");
					
					lblEncryptStatusBox.setText("Decryption In Progress ...");
				}
				
				String cmdRetStr = cmdInterpretor.runCommand();
								
				if(cmdRetStr.compareTo("") != 0)
				{
					lblEncryptStatusBox.setText(cmdRetStr);

					if(chckbxEncryptDecryptRSAOaep.isSelected() == true && comboSymetricAsymetric.getSelectedIndex() == COMBO_INDEX_ASYMETRIC_CRYPTO_ENCRYPT)
					{
						lblEncryptStatusBox.setText("RSA Oaep Error: Hash Function not supported for given RSA key length, key length should be more than digest length");
					}
				}
				else
				{
					lblEncryptStatusBox.setText("Processing Completed");
				}
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnStartFileEncrypt.setBounds(269, 78, 221, 25);
		groupBoxEncryptFiles.add(btnStartFileEncrypt);
		lblEncyptStatus.setBounds(10, 109, 46, 14);
		
		groupBoxEncryptFiles.add(lblEncyptStatus);
		lblEncryptStatusBox.setBounds(58, 109, 772, 14);
		groupBoxEncryptFiles.add(lblEncryptStatusBox);
		
		btnSwapFilesEncDec.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				String tmp = txtEncryptDecryptFileInput.getText();
				
				txtEncryptDecryptFileInput.setText(txtEncryptDecryptFileOutput.getText());
				txtEncryptDecryptFileOutput.setText(tmp);
			}
		});
		
		btnSwapFilesEncDec.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		btnSwapFilesEncDec.setBounds(741, 78, 89, 25);
		
		groupBoxEncryptFiles.add(btnSwapFilesEncDec);
		
		groupBoxEncryptSymetricParams.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxEncryptSymetricParams.setBounds(10, 44, 840, 34);
		encrypt.add(groupBoxEncryptSymetricParams);
		groupBoxEncryptSymetricParams.setLayout(null);
		comboEncryptCiphers.setBounds(97, 7, 153, 22);
		groupBoxEncryptSymetricParams.add(comboEncryptCiphers);
		
		lblEncryptAlgorithm.setBounds(21, 11, 66, 14);
		groupBoxEncryptSymetricParams.add(lblEncryptAlgorithm);
		
		lblEncryptPassPhrase.setBounds(277, 11, 92, 14);
		groupBoxEncryptSymetricParams.add(lblEncryptPassPhrase);

		pwdEncryptAddPassPhrase.setBounds(362, 8, 166, 20);
		groupBoxEncryptSymetricParams.add(pwdEncryptAddPassPhrase);
		pwdEncryptAddPassPhrase.setText("1234567890");
		
		chckbxEncryptAddSalt.setBounds(549, 7, 78, 23);
		groupBoxEncryptSymetricParams.add(chckbxEncryptAddSalt);
		
		chckbxEncryptBase64.setBounds(656, 7, 137, 23);
		groupBoxEncryptSymetricParams.add(chckbxEncryptBase64);
		
		groupBoxEncryptASymetricPrivate.setLayout(null);
		groupBoxEncryptASymetricPrivate.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxEncryptASymetricPrivate.setBounds(10, 89, 840, 43);
		encrypt.add(groupBoxEncryptASymetricPrivate);
		txtAsymetricKeyFile.setEditable(false);
		
		txtAsymetricKeyFile.setEnabled(false);
		txtAsymetricKeyFile.setText("Symetric key Crypto Selected this is Not Applicable ");
		txtAsymetricKeyFile.setColumns(10);
		txtAsymetricKeyFile.setBounds(10, 12, 721, 20);
		groupBoxEncryptASymetricPrivate.add(txtAsymetricKeyFile);
		
		btnBrowseAsymKeyFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(btnBrowseAsymKeyFile.isEnabled() == false)
				{
					return;
				}
				
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtAsymetricKeyFile.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseAsymKeyFile.setEnabled(false);
		
		btnBrowseAsymKeyFile.setBounds(741, 11, 89, 23);
		groupBoxEncryptASymetricPrivate.add(btnBrowseAsymKeyFile);
		comboSymetricAsymetric.setBounds(10, 11, 246, 22);
		
		encrypt.add(comboSymetricAsymetric);
		chckbxEncryptDecryptRSAOaep.setEnabled(false);
		
		chckbxEncryptDecryptRSAOaep.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(chckbxEncryptDecryptRSAOaep.isSelected() == true)
				{
					comboEncryptDecryptHashFunctions.setEnabled(true);
					lblEncryptDecryptHashFunction.setEnabled(true);
				}
				
				if(chckbxEncryptDecryptRSAOaep.isSelected() == false)
				{
					comboEncryptDecryptHashFunctions.setEnabled(false);
					lblEncryptDecryptHashFunction.setEnabled(false);
				}
			}
		});
		
		
		chckbxEncryptDecryptRSAOaep.setBounds(379, 11, 129, 23);
		encrypt.add(chckbxEncryptDecryptRSAOaep);
		comboEncryptDecryptHashFunctions.setEnabled(false);
		comboEncryptDecryptHashFunctions.setBounds(649, 11, 153, 22);
		encrypt.add(comboEncryptDecryptHashFunctions);
		lblEncryptDecryptHashFunction.setEnabled(false);
		
		lblEncryptDecryptHashFunction.setBounds(553, 15, 109, 14);
		encrypt.add(lblEncryptDecryptHashFunction);
				
		/* *** add list of ciphers to combo box Start *** */
		
		cmdInterpretor.addCommandLineStr("openssl"); 
		cmdInterpretor.addCommandLineStr("enc");
		cmdInterpretor.addCommandLineStr("-list");
		
		String [] ciphers = cmdInterpretor.runCommand().split("\n");
		
		displayCmdInTextAreaAndClear();
		
		for(int i = 0; i < ciphers.length; i++)
		{
			String [] comboItem = ciphers[i].split(" -");
			
			for(int j = 0; j < comboItem.length; j++)
			{
				if(comboItem[j].startsWith("-") == false)
				{
					comboItem[j] = "-" + comboItem[j];
				}
				
				if((i != 0) || (j !=0))
				{
					comboEncryptCiphers.addItem(comboItem[j]);
					comboKeyGenCipher.addItem(comboItem[j]);
					
					if(comboItem[j].contains("cbc"))
					{
						comboEncryptCiphersCmac.addItem(comboItem[j].replaceFirst("-", ""));
					}
				}
			}
		}
		
		/* *** add list of ciphers to combo box End *** */
		
		/* *** add list of Hash Functions to combo box Start *** */
		comboSignVerifyRSAMgf1.setEnabled(false);
		
		comboSignVerifyRSAMgf1.addItem("Use Signing Digest");
		comboSignVerifyHashingFunction.addItem("Use Already Hashed Input File");
		
		cmdInterpretor.addCommandLineStr("openssl"); 
		cmdInterpretor.addCommandLineStr("dgst");
		cmdInterpretor.addCommandLineStr("-list");
		
		String [] hashFunc = cmdInterpretor.runCommand().split("\n");
		
		displayCmdInTextAreaAndClear();
		
		for(int i = 0; i < hashFunc.length; i++)
		{
			String [] comboItem = hashFunc[i].split(" -");
			
			for(int j = 0; j < comboItem.length; j++)
			{
				if(comboItem[j].startsWith("-") == false)
				{
					comboItem[j] = "-" + comboItem[j];
				}
				
				if((i != 0) || (j !=0))
				{
					comboHashFunctions.addItem(comboItem[j]);
					comboEncryptDecryptHashFunctions.addItem(comboItem[j]);
					comboSignVerifyHashingFunction.addItem(comboItem[j]);
					comboSignVerifyRSAMgf1.addItem(comboItem[j]);
					comboBoxCertHashFuncRoot.addItem(comboItem[j].replace("-", ""));
					comboBoxCertHashFuncIntermediate.addItem(comboItem[j].replace("-", ""));
					comboBoxCertHashFuncEndEntity.addItem(comboItem[j].replace("-", ""));
				}
			}
		}
		
		comboBoxCertHashFuncRoot.setSelectedIndex(11);
		comboBoxCertHashFuncIntermediate.setSelectedIndex(11);
		comboBoxCertHashFuncEndEntity.setSelectedIndex(11);
		
		/* *** add list of Hash Functions to combo box End *** */
		
		tabbedPane.addTab("Hash & Mac", null, hashAndMac, null);
		hashAndMac.setLayout(null);
		groupBoxHashingParams.setLayout(null);
		groupBoxHashingParams.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxHashingParams.setBounds(10, 11, 840, 196);
		
		hashAndMac.add(groupBoxHashingParams);
		comboHashFunctions.setBounds(129, 54, 153, 22);
		
		groupBoxHashingParams.add(comboHashFunctions);
		lblHashFunction.setBounds(10, 58, 109, 14);
		
		groupBoxHashingParams.add(lblHashFunction);
		
		JLabel lblEncryptAlgorithmCMac = new JLabel("Cipher:");
		lblEncryptAlgorithmCMac.setBounds(601, 62, 66, 14);
		groupBoxHashingParams.add(lblEncryptAlgorithmCMac);
		comboEncryptCiphersCmac.setEditable(true);
		comboEncryptCiphersCmac.setEnabled(false);
		
		comboEncryptCiphersCmac.setBounds(677, 58, 153, 22);
		groupBoxHashingParams.add(comboEncryptCiphersCmac);
		
		JLabel lblEncryptPassPhraseMac = new JLabel("Pass Phrase:");
		lblEncryptPassPhraseMac.setBounds(313, 63, 92, 14);
		groupBoxHashingParams.add(lblEncryptPassPhraseMac);
		
		passwordFieldMac = new JPasswordField();
		passwordFieldMac.setEnabled(false);
		passwordFieldMac.setText("1234567890");
		passwordFieldMac.setBounds(405, 60, 166, 20);
		groupBoxHashingParams.add(passwordFieldMac);
		
		JRadioButton rdbtnHmac = new JRadioButton("HMAC Generate");
		rdbtnHmac.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				passwordFieldMac.setEnabled(true);
				comboEncryptCiphersCmac.setEnabled(false);
			}
		});
		buttonGroupHash.add(rdbtnHmac);
		rdbtnHmac.setBounds(129, 17, 142, 23);
		groupBoxHashingParams.add(rdbtnHmac);
		
		JRadioButton rdbtnCmac = new JRadioButton("CMAC Generate");
		rdbtnCmac.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				passwordFieldMac.setEnabled(true);
				comboEncryptCiphersCmac.setEnabled(true);
			}
		});
		buttonGroupHash.add(rdbtnCmac);
		rdbtnCmac.setBounds(313, 17, 131, 23);
		groupBoxHashingParams.add(rdbtnCmac);
		
		txtHashInputFile = new JTextField();
		txtHashInputFile.setBounds(10, 104, 721, 20);
		groupBoxHashingParams.add(txtHashInputFile);
		txtHashInputFile.setText("Input File to be hashed");
		txtHashInputFile.setEditable(false);
		txtHashInputFile.setColumns(10);
		btnBrowseHashInput.setBounds(741, 103, 89, 23);
		groupBoxHashingParams.add(btnBrowseHashInput);
		btnStartFileHashing.setBounds(313, 137, 154, 23);
		groupBoxHashingParams.add(btnStartFileHashing);
		lblHashStatusBox.setBounds(58, 171, 772, 14);
		groupBoxHashingParams.add(lblHashStatusBox);
		lblHashStatus.setBounds(10, 171, 46, 14);
		groupBoxHashingParams.add(lblHashStatus);
		
		rdbtnHash = new JRadioButton("Hashing");
		rdbtnHash.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				passwordFieldMac.setEnabled(false);
				comboEncryptCiphersCmac.setEnabled(false);
			}
		});
		buttonGroupHash.add(rdbtnHash);
		rdbtnHash.setBounds(10, 17, 92, 23);
		groupBoxHashingParams.add(rdbtnHash);
		rdbtnHash.setSelected(true);
		
		btnStartFileHashing.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(hashMsgFileSelected == false)
				{
					lblHashStatusBox.setText("Error: !!! Select the file !!!");
					return;
				}
				
				String inputFile = "\"" + txtHashInputFile.getText() + "\"";
				String outputFile = "\"" + txtHashInputFile.getText() + "_" + ((String)comboHashFunctions.getSelectedItem()).replace(" ", "").replace("-", "") + "_hashed.bin" + "\"";
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("dgst");
				cmdInterpretor.addCommandLineStr((String)comboHashFunctions.getSelectedItem());
				
				if(rdbtnHmac.isSelected())
				{
					outputFile = "\"" + txtHashInputFile.getText() + "_" + ((String)comboHashFunctions.getSelectedItem()).replace(" ", "").replace("-", "") + "_HMac.bin" + "\"";
					
					cmdInterpretor.addCommandLineStr("-mac");
					cmdInterpretor.addCommandLineStr("hmac");
					cmdInterpretor.addCommandLineStr("-macopt");
					cmdInterpretor.addCommandLineStr("key:"  + new String(passwordFieldMac.getPassword()));
				}
					
				if(rdbtnCmac.isSelected())
				{
					outputFile = "\"" + txtHashInputFile.getText() + "_" + ((String)comboHashFunctions.getSelectedItem()).replace(" ", "").replace("-", "") + "_CMac.bin" + "\"";
					
					if(!ispasswordLenghtOk())
					{
						cmdInterpretor.clearCommandLineStr();
						
						return;
					}
					
					cmdInterpretor.addCommandLineStr("-mac");
					cmdInterpretor.addCommandLineStr("cmac");
					cmdInterpretor.addCommandLineStr("-macopt");
					cmdInterpretor.addCommandLineStr("cipher:"  + comboEncryptCiphersCmac.getSelectedItem());
					cmdInterpretor.addCommandLineStr("-macopt");
					cmdInterpretor.addCommandLineStr("key:"  + new String(passwordFieldMac.getPassword()));
				}	

				cmdInterpretor.addCommandLineStr("-out");
				cmdInterpretor.addCommandLineStr(outputFile);
				cmdInterpretor.addCommandLineStr(inputFile);

				
				String cmdRetStr = cmdInterpretor.runCommand();
								
				if(cmdRetStr.compareTo("") != 0)
				{
					lblHashStatusBox.setText(cmdRetStr);
				}
				else
				{
					lblHashStatusBox.setText("Hashing Completed, " + outputFile.split("\\\\")[ outputFile.split("\\\\").length - 1] + " file generated in same path ...");
				}
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnBrowseHashInput.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtHashInputFile.setText(fileChooser.getSelectedFile().getPath());
					
					lblHashStatusBox.setText("Input File to Be Hashed selected");
					
					hashMsgFileSelected = true;
				}
				
			}
		});
		
		groupBoxHashText.setLayout(null);
		groupBoxHashText.setToolTipText("Input for Encryption");
		groupBoxHashText.setName("");
		groupBoxHashText.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxHashText.setAutoscrolls(true);
		groupBoxHashText.setBounds(10, 218, 840, 287);
		hashAndMac.add(groupBoxHashText);
		scrollPane_3.setBounds(10, 11, 820, 115);
		
		groupBoxHashText.add(scrollPane_3);
		scrollPane_3.setViewportView(textAreaHashInput);
		
		textAreaHashInput.addKeyListener(new KeyAdapter() 
		{
			@Override
			public void keyPressed(KeyEvent arg0) 
			{
				if(arg0.getKeyCode() == 112)
				{
					File tmpFile = new File("tmp.txt");
					
					try 
					{
						tmpFile.createNewFile();
						
						FileWriter tmpFileWriter = new FileWriter(tmpFile);
						tmpFileWriter.write(textAreaHashInput.getText());
						tmpFileWriter.close();
					} 
					catch (IOException e) 
					{
						e.printStackTrace();
					}
					
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("dgst");
					cmdInterpretor.addCommandLineStr((String)comboHashFunctions.getSelectedItem());
					cmdInterpretor.addCommandLineStr("tmp.txt");
					
					String cmdOutputStr = cmdInterpretor.runCommand();
					
					textAreaHashOutput.setText(cmdOutputStr);
					displayCmdInTextAreaAndClear();
					
					tmpFile.delete();
				}
				
				if(arg0.getKeyCode() == 27)
				{
					textAreaHashInput.setText(null);
				}
				
			}
		});
		
		textAreaHashInput.setText("Click to Add or Copy Input Text");
		scrollPane_4.setBounds(10, 163, 820, 113);
		
		groupBoxHashText.add(scrollPane_4);
		scrollPane_4.setViewportView(textAreaHashOutput);
		
		textAreaHashOutput.addKeyListener(new KeyAdapter() 
		{
			@Override
			public void keyPressed(KeyEvent arg0) 
			{
				if(arg0.getKeyCode() == 27)
				{
					textAreaHashOutput.setText(null);
				}
			}
		});
		
		textAreaHashOutput.setText("Hashed Text will be displayed here ");
		
		lblPressescKey.setFont(new Font("Tahoma", Font.BOLD, 12));
		lblPressescKey.setBounds(226, 138, 449, 14);
		groupBoxHashText.add(lblPressescKey);
		signAndVerify.setAutoscrolls(true);
		
		tabbedPane.addTab("Sign & Verify", null, signAndVerify, null);
		signAndVerify.setLayout(null);
		
		JPanel groupBoxEncryptSymetricParams_1 = new JPanel();
		groupBoxEncryptSymetricParams_1.setLayout(null);
		groupBoxEncryptSymetricParams_1.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxEncryptSymetricParams_1.setBounds(9, 51, 840, 71);
		signAndVerify.add(groupBoxEncryptSymetricParams_1);
		
		JLabel lblSignVerifyRSAPaddingMode = new JLabel("RSA Padding Mode");
		lblSignVerifyRSAPaddingMode.setEnabled(false);
		lblSignVerifyRSAPaddingMode.setBounds(10, 42, 108, 14);
		groupBoxEncryptSymetricParams_1.add(lblSignVerifyRSAPaddingMode);
		
		comboSignVerifyRSAPaddingMode.setBounds(122, 38, 117, 22);
		groupBoxEncryptSymetricParams_1.add(comboSignVerifyRSAPaddingMode);
		
		lblSignVerifyRSASaltLength.setEnabled(false);
		lblSignVerifyRSASaltLength.setBounds(280, 42, 108, 14);
		groupBoxEncryptSymetricParams_1.add(lblSignVerifyRSASaltLength);
		
		comboSignVerifyRSASaltLength.setBounds(382, 38, 117, 22);
		groupBoxEncryptSymetricParams_1.add(comboSignVerifyRSASaltLength);
		
		lblSignVerifyRsaMgf1.setEnabled(false);
		lblSignVerifyRsaMgf1.setBounds(540, 42, 103, 14);
		groupBoxEncryptSymetricParams_1.add(lblSignVerifyRsaMgf1);
		
		comboSignVerifyRSAMgf1.setBounds(653, 38, 155, 22);
		groupBoxEncryptSymetricParams_1.add(comboSignVerifyRSAMgf1);
		chckbxSignVerifyRSASignature.setBounds(6, 7, 118, 23);
		groupBoxEncryptSymetricParams_1.add(chckbxSignVerifyRSASignature);
		
		chckbxSignVerifyRSASignature.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(chckbxSignVerifyRSASignature.isSelected() == true)
				{
					lblSignVerifyRSAPaddingMode.setEnabled(true);
					comboSignVerifyRSAPaddingMode.setEnabled(true);
					
					comboSignVerifyRSAPaddingMode.getItemListeners()[0].itemStateChanged(null);
				}
				
				if(chckbxSignVerifyRSASignature.isSelected() == false)
				{
					lblSignVerifyRSAPaddingMode.setEnabled(false);
					comboSignVerifyRSAPaddingMode.setEnabled(false);
					comboSignVerifyRSASaltLength.setEnabled(false);
					lblSignVerifyRsaMgf1.setEnabled(false);
					comboSignVerifyRSAMgf1.setEnabled(false);
					lblSignVerifyRSASaltLength.setEnabled(false);
				}
			}
		});
		
		JPanel groupBoxSignVerifyVerifyFiles = new JPanel();
		groupBoxSignVerifyVerifyFiles.setLayout(null);
		groupBoxSignVerifyVerifyFiles.setToolTipText("Output of Encryption");
		groupBoxSignVerifyVerifyFiles.setName("");
		groupBoxSignVerifyVerifyFiles.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxSignVerifyVerifyFiles.setBounds(9, 273, 840, 156);
		signAndVerify.add(groupBoxSignVerifyVerifyFiles);
		
		txtSignVerifyVerifyInputFile = new JTextField();
		txtSignVerifyVerifyInputFile.setEditable(false);
		txtSignVerifyVerifyInputFile.setText("Select signed file");
		txtSignVerifyVerifyInputFile.setColumns(10);
		txtSignVerifyVerifyInputFile.setBounds(10, 47, 721, 20);
		groupBoxSignVerifyVerifyFiles.add(txtSignVerifyVerifyInputFile);
		
		txtSignVerifyVerifyPubKeyFile = new JTextField();
		txtSignVerifyVerifyPubKeyFile.setEditable(false);
		txtSignVerifyVerifyPubKeyFile.setText("Select Public Key file to be used in verification");
		txtSignVerifyVerifyPubKeyFile.setColumns(10);
		txtSignVerifyVerifyPubKeyFile.setBounds(10, 15, 721, 20);
		groupBoxSignVerifyVerifyFiles.add(txtSignVerifyVerifyPubKeyFile);
		
		JButton btnBrowseSignVerifyVerifyPubKeyFile = new JButton("Browse");
		btnBrowseSignVerifyVerifyPubKeyFile.setBounds(741, 14, 89, 23);
		groupBoxSignVerifyVerifyFiles.add(btnBrowseSignVerifyVerifyPubKeyFile);
		
		JButton btnBrowseSignVerifyVerifyInputFile = new JButton("Browse");
		btnBrowseSignVerifyVerifyInputFile.setBounds(741, 46, 89, 23);
		groupBoxSignVerifyVerifyFiles.add(btnBrowseSignVerifyVerifyInputFile);
		
		btnStartVerify.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				String pubKeyFile = "\"" + txtSignVerifyVerifyPubKeyFile.getText() + "\"";
				String inputFile = "\"" + txtSignVerifyVerifyInputFile.getText() + "\"";
				String originalFile = "\"" + txtSignVerifyToBeVerifiedAgainstFile.getText() + "\"";
				String tmpInputFile = originalFile;
				
				File tmpFile = new File("tmp.txt");
				
				try 
				{
					tmpFile.createNewFile();
				} 
				catch (IOException e) 
				{
					e.printStackTrace();
				}
				
				if(comboSignVerifyHashingFunction.getSelectedIndex() != 0)
				{
					tmpInputFile = tmpFile.getName();
					
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("dgst");
					cmdInterpretor.addCommandLineStr((String)comboSignVerifyHashingFunction.getSelectedItem());
					cmdInterpretor.addCommandLineStr("-binary");
					cmdInterpretor.addCommandLineStr("-out");
					cmdInterpretor.addCommandLineStr(tmpInputFile);
					cmdInterpretor.addCommandLineStr(originalFile);
					
					cmdInterpretor.runCommand();
					
					displayCmdInTextAreaAndClear();
				}
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("pkeyutl ");
				cmdInterpretor.addCommandLineStr("-verify");
				cmdInterpretor.addCommandLineStr("-pubin");
				cmdInterpretor.addCommandLineStr("-inkey");
				cmdInterpretor.addCommandLineStr(pubKeyFile);
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(tmpInputFile);
				cmdInterpretor.addCommandLineStr("-sigfile");
				cmdInterpretor.addCommandLineStr(inputFile);
				
				if(chckbxSignVerifyRSASignature.isSelected() == true)
				{
					cmdInterpretor.addCommandLineStr("-pkeyopt");
					cmdInterpretor.addCommandLineStr("rsa_padding_mode:" + (String)comboSignVerifyRSAPaddingMode.getSelectedItem());
									
					if(((String)comboSignVerifyRSAPaddingMode.getSelectedItem()).compareTo("pss") == 0)
					{
						cmdInterpretor.addCommandLineStr("-pkeyopt");
						cmdInterpretor.addCommandLineStr("rsa_pss_saltlen:" + (String)comboSignVerifyRSASaltLength.getSelectedItem());
						
						if(comboSignVerifyRSAMgf1.getSelectedIndex() != 0)
						{
							cmdInterpretor.addCommandLineStr("-pkeyopt");
							cmdInterpretor.addCommandLineStr("rsa_mgf1_md:" + ((String)comboSignVerifyRSAMgf1.getSelectedItem()).replaceAll("-", ""));
						}
					}
				}
				
				String cmdRetStr = cmdInterpretor.runCommand();
				
				displayCmdInTextAreaAndClear();
								
				textAreaSignVerify.setText(cmdRetStr);
				
				tmpFile.delete();
			}
		});
		
		btnStartVerify.setBounds(281, 109, 190, 34);
		groupBoxSignVerifyVerifyFiles.add(btnStartVerify);
		
		txtSignVerifyToBeVerifiedAgainstFile = new JTextField();
		txtSignVerifyToBeVerifiedAgainstFile.setText("Select Original File to verify against signed file");
		txtSignVerifyToBeVerifiedAgainstFile.setEditable(false);
		txtSignVerifyToBeVerifiedAgainstFile.setColumns(10);
		txtSignVerifyToBeVerifiedAgainstFile.setBounds(10, 78, 721, 20);
		groupBoxSignVerifyVerifyFiles.add(txtSignVerifyToBeVerifiedAgainstFile);
		
		JButton btnBrowseSignVerifyToBeVerifiedAgainstFile = new JButton("Browse");
		
		btnBrowseSignVerifyToBeVerifiedAgainstFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtSignVerifyToBeVerifiedAgainstFile.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseSignVerifyToBeVerifiedAgainstFile.setBounds(741, 80, 89, 23);
		groupBoxSignVerifyVerifyFiles.add(btnBrowseSignVerifyToBeVerifiedAgainstFile);
		lblKeyGenPublicKeyFileFormatRSA_1_1.setBounds(597, 125, 132, 14);
		
		groupBoxSignVerifyVerifyFiles.add(lblKeyGenPublicKeyFileFormatRSA_1_1);
		comboSignVerifyVerifyKeyFileFormat.setBounds(741, 120, 89, 22);
		
		groupBoxSignVerifyVerifyFiles.add(comboSignVerifyVerifyKeyFileFormat);
		
		JPanel groupBoxSignVerifySignFiles = new JPanel();
		groupBoxSignVerifySignFiles.setLayout(null);
		groupBoxSignVerifySignFiles.setToolTipText("Output of Encryption");
		groupBoxSignVerifySignFiles.setName("");
		groupBoxSignVerifySignFiles.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxSignVerifySignFiles.setBounds(9, 133, 840, 129);
		signAndVerify.add(groupBoxSignVerifySignFiles);
		
		txtSignVerifySignInputFile = new JTextField();
		txtSignVerifySignInputFile.setText("Select File to be Signed");
		txtSignVerifySignInputFile.setEditable(false);
		txtSignVerifySignInputFile.setColumns(10);
		txtSignVerifySignInputFile.setBounds(10, 47, 721, 20);
		groupBoxSignVerifySignFiles.add(txtSignVerifySignInputFile);
		
		txtSignVerifySignPrivKeyFile = new JTextField();
		txtSignVerifySignPrivKeyFile.setText("Select Private Key file to be used in signing");
		txtSignVerifySignPrivKeyFile.setEditable(false);
		txtSignVerifySignPrivKeyFile.setColumns(10);
		txtSignVerifySignPrivKeyFile.setBounds(10, 15, 721, 20);
		groupBoxSignVerifySignFiles.add(txtSignVerifySignPrivKeyFile);
		
		JButton btnBrowseSignVerifySigningPrivKeyFile = new JButton("Browse");
		
		btnBrowseSignVerifySigningPrivKeyFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtSignVerifySignPrivKeyFile.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseSignVerifyVerifyPubKeyFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtSignVerifyVerifyPubKeyFile.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseSignVerifySignInputFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtSignVerifySignInputFile.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseSignVerifyVerifyInputFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtSignVerifyVerifyInputFile.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseSignVerifySigningPrivKeyFile.setBounds(741, 14, 89, 23);
		groupBoxSignVerifySignFiles.add(btnBrowseSignVerifySigningPrivKeyFile);

		btnBrowseSignVerifySignInputFile.setBounds(741, 46, 89, 23);
		groupBoxSignVerifySignFiles.add(btnBrowseSignVerifySignInputFile);
		
		JButton btnStartSign = new JButton("Start Signing");
		
		btnStartSign.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				String prvKeyFile = "\"" + txtSignVerifySignPrivKeyFile.getText() + "\"";
				String inputFile = "\"" + txtSignVerifySignInputFile.getText() + "\"";
				String outputFile = "\"" + txtSignVerifySignInputFile.getText() + "_" + ((String)comboSignVerifyHashingFunction.getSelectedItem()).replace(" ", "").replace("-", "") + "_signed.bin" + "\"";
				String tmpInputFile = inputFile;
				
				File tmpFile = new File("tmp.txt");
				
				try 
				{
					tmpFile.createNewFile();
				} 
				catch (IOException e) 
				{
					e.printStackTrace();
				}
				
				if(comboSignVerifyHashingFunction.getSelectedIndex() != 0)
				{
					tmpInputFile = tmpFile.getName();
					
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("dgst");
					cmdInterpretor.addCommandLineStr((String)comboSignVerifyHashingFunction.getSelectedItem());
					cmdInterpretor.addCommandLineStr("-binary");
					cmdInterpretor.addCommandLineStr("-out");
					cmdInterpretor.addCommandLineStr(tmpInputFile);
					cmdInterpretor.addCommandLineStr(inputFile);
					
					cmdInterpretor.runCommand();
					
					displayCmdInTextAreaAndClear();
				}
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("pkeyutl ");
				cmdInterpretor.addCommandLineStr("-sign");
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(tmpInputFile);
				cmdInterpretor.addCommandLineStr("-inkey");
				cmdInterpretor.addCommandLineStr(prvKeyFile);
				cmdInterpretor.addCommandLineStr("-keyform");
				cmdInterpretor.addCommandLineStr((String) comboSignVerifySigningKeyFileFormat.getSelectedItem());
				cmdInterpretor.addCommandLineStr("-out");
				cmdInterpretor.addCommandLineStr(outputFile);
				
				if(chckbxSignVerifyRSASignature.isSelected() == true)
				{
					cmdInterpretor.addCommandLineStr("-pkeyopt");
					cmdInterpretor.addCommandLineStr("rsa_padding_mode:" + (String)comboSignVerifyRSAPaddingMode.getSelectedItem());
									
					if(((String)comboSignVerifyRSAPaddingMode.getSelectedItem()).compareTo("pss") == 0)
					{
						cmdInterpretor.addCommandLineStr("-pkeyopt");
						cmdInterpretor.addCommandLineStr("rsa_pss_saltlen:" + (String)comboSignVerifyRSASaltLength.getSelectedItem());
						
						if(comboSignVerifyRSAMgf1.getSelectedIndex() != 0)
						{
							cmdInterpretor.addCommandLineStr("-pkeyopt");
							cmdInterpretor.addCommandLineStr("rsa_mgf1_md:" + ((String)comboSignVerifyRSAMgf1.getSelectedItem()).replaceAll("-", ""));
						}
					}
				}
				
				String cmdRetStr = cmdInterpretor.runCommand();
				
				displayCmdInTextAreaAndClear();
				
				tmpFile.delete();
								
				if(cmdRetStr.compareTo("") != 0)
				{
					textAreaSignVerify.setText(cmdRetStr);
				}
				else
				{
					cmdInterpretor.addCommandLineStr("openssl"); 
					cmdInterpretor.addCommandLineStr("base64");
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr(outputFile);
										
					textAreaSignVerify.setText("Signing Completed: " + outputFile.split("\\\\")[outputFile.split("\\\\").length - 1] + " file generated. \n\n Base 64 format output:\n" + cmdInterpretor.runCommand());
					
					displayCmdInTextAreaAndClear();
				}
			}
		});
		
		btnStartSign.setBounds(274, 78, 190, 33);
		groupBoxSignVerifySignFiles.add(btnStartSign);
		lblKeyGenPublicKeyFileFormatRSA_1.setBounds(595, 88, 132, 14);
		
		groupBoxSignVerifySignFiles.add(lblKeyGenPublicKeyFileFormatRSA_1);
		comboSignVerifySigningKeyFileFormat.setBounds(741, 86, 89, 22);
		
		groupBoxSignVerifySignFiles.add(comboSignVerifySigningKeyFileFormat);
		comboSignVerifyHashingFunction.setBounds(369, 16, 226, 22);
		signAndVerify.add(comboSignVerifyHashingFunction);
		
		JLabel lblSignVerifyHashingFunction = new JLabel("Hash Function to be Used:");
		lblSignVerifyHashingFunction.setBounds(215, 20, 157, 14);
		signAndVerify.add(lblSignVerifyHashingFunction);
		scrollPane_5.setBounds(9, 440, 841, 65);
		
		signAndVerify.add(scrollPane_5);
		scrollPane_5.setViewportView(textAreaSignVerify);
				
		tabbedPane.addTab("Certificate Management", null, certificateManagement, null);
		certificateManagement.setLayout(null);
		
		JPanel groupBoxCertVerify = new JPanel();
		groupBoxCertVerify.setLayout(null);
		groupBoxCertVerify.setToolTipText("Output of Encryption");
		groupBoxCertVerify.setName("");
		groupBoxCertVerify.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxCertVerify.setBounds(10, 240, 840, 124);
		certificateManagement.add(groupBoxCertVerify);
		
		txtCertSelectIntermediate = new JTextField();
		txtCertSelectIntermediate.setText("Select Intermediate Certificate");
		txtCertSelectIntermediate.setEditable(false);
		txtCertSelectIntermediate.setColumns(10);
		txtCertSelectIntermediate.setBounds(10, 42, 616, 20);
		groupBoxCertVerify.add(txtCertSelectIntermediate);
		
		txtCertSelectRoot = new JTextField();
		txtCertSelectRoot.setText("Select Root Certificate");
		txtCertSelectRoot.setEditable(false);
		txtCertSelectRoot.setColumns(10);
		txtCertSelectRoot.setBounds(10, 12, 616, 20);
		groupBoxCertVerify.add(txtCertSelectRoot);
		
		
		btnBrowseCertSelectRoot.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtCertSelectRoot.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseCertSelectRoot.setBounds(636, 11, 80, 23);
		groupBoxCertVerify.add(btnBrowseCertSelectRoot);
		
		btnBrowseCertSelectIntermediate.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtCertSelectIntermediate.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseCertSelectIntermediate.setBounds(636, 41, 80, 23);
		groupBoxCertVerify.add(btnBrowseCertSelectIntermediate);
		
		btnVerifyCertChain.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{				
				String rootCertFile = "\"" + txtCertSelectRoot.getText() + "\"";
				String intermediateCertFile = "\"" + txtCertSelectIntermediate.getText() + "\"";
				String endEntityCertFile = "\"" + txtCertSelectEndEntity.getText() + "\"";

				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("verify");
				cmdInterpretor.addCommandLineStr("-CAfile");
				cmdInterpretor.addCommandLineStr(rootCertFile);
				
				if(chckbxCertVerifyIgnoreIntermediate.isSelected() == false)
				{
					cmdInterpretor.addCommandLineStr("-untrusted");
					cmdInterpretor.addCommandLineStr(intermediateCertFile);
				}
			
				cmdInterpretor.addCommandLineStr(endEntityCertFile);
				
				textCertStatus.setText(cmdInterpretor.runCommand());
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnVerifyCertChain.setBounds(224, 95, 221, 20);
		groupBoxCertVerify.add(btnVerifyCertChain);
		
		txtCertSelectEndEntity = new JTextField();
		txtCertSelectEndEntity.setText("Select End Entity Certificate");
		txtCertSelectEndEntity.setEditable(false);
		txtCertSelectEndEntity.setColumns(10);
		txtCertSelectEndEntity.setBounds(10, 70, 616, 20);
		groupBoxCertVerify.add(txtCertSelectEndEntity);
		
		btnBrowseCertSelectEndEntity.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtCertSelectEndEntity.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		
		btnBrowseCertSelectEndEntity.setBounds(636, 69, 80, 23);
		groupBoxCertVerify.add(btnBrowseCertSelectEndEntity);
		btnDisplayCertEndEntity.setBounds(726, 69, 104, 23);
		
		groupBoxCertVerify.add(btnDisplayCertEndEntity);
		btnDisplayCertIntermediate.setBounds(726, 41, 104, 23);
		
		groupBoxCertVerify.add(btnDisplayCertIntermediate);
		btnDisplayCertRoot.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				String certFile = "\"" + txtCertSelectRoot.getText() + "\"";
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("x509");
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(certFile);
				cmdInterpretor.addCommandLineStr("-text"); 
				cmdInterpretor.addCommandLineStr("-noout");
				
				textCertStatus.setText(cmdInterpretor.runCommand());
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnDisplayCertIntermediate.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				String certFile = "\"" + txtCertSelectIntermediate.getText() + "\"";
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("x509");
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(certFile);
				cmdInterpretor.addCommandLineStr("-text"); 
				cmdInterpretor.addCommandLineStr("-noout");
				
				textCertStatus.setText(cmdInterpretor.runCommand());
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnDisplayCertEndEntity.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				String certFile = "\"" + txtCertSelectEndEntity.getText() + "\"";
				
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("x509");
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(certFile);
				cmdInterpretor.addCommandLineStr("-text"); 
				cmdInterpretor.addCommandLineStr("-noout");
				
				textCertStatus.setText(cmdInterpretor.runCommand());
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnDisplayCertRoot.setBounds(726, 11, 104, 23);
		
		groupBoxCertVerify.add(btnDisplayCertRoot);
		
		chckbxCertVerifyIgnoreIntermediate.setBounds(636, 96, 154, 18);
		groupBoxCertVerify.add(chckbxCertVerifyIgnoreIntermediate);
		
		JScrollPane scrollPaneCertStatusDisplay = new JScrollPane();
		scrollPaneCertStatusDisplay.setBounds(10, 369, 840, 136);
		certificateManagement.add(scrollPaneCertStatusDisplay);
		
		scrollPaneCertStatusDisplay.setViewportView(textCertStatus);
		textCertStatus.setText("Status Display");
		groupBoxCertGenerate.setLayout(null);
		groupBoxCertGenerate.setToolTipText("Output of Encryption");
		groupBoxCertGenerate.setName("");
		groupBoxCertGenerate.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxCertGenerate.setBounds(10, 5, 840, 232);
		
		certificateManagement.add(groupBoxCertGenerate);
		
		btnGenerateCertificates.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(certificateWsSelected == false)
				{
					textCertStatus.setText("Error: Select the path which key, csr and certificate files to be generated !!!");
					return;
				}
				
				String [] subjCertAttributes = certGenerateCreateSubjectAttribsInStr();
				String[] generatedCertificateRetStr;
				
				generateConfigFilesToWs();
				
				generatedCertificateRetStr = generateCertificate(true, "Root", "", "", (String)tableCertAttributes.getValueAt(0, CERT_ATTRB_COLUMN_ROOT + 1), subjCertAttributes[CERT_ATTRB_COLUMN_ROOT], certGenerateGetKeyMethod(comboBoxCertKeyMethodRoot, CERT_ATTRB_COLUMN_ROOT), "root.config", (String)comboBoxCertHashFuncRoot.getSelectedItem());
				
				generatedCertificateRetStr = generateCertificate(false, "Intermediate", generatedCertificateRetStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTFILE], generatedCertificateRetStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTKEYFILE], (String)tableCertAttributes.getValueAt(0, CERT_ATTRB_COLUMN_INTERMEDIATE + 1), subjCertAttributes[CERT_ATTRB_COLUMN_INTERMEDIATE], certGenerateGetKeyMethod(comboBoxCertKeyMethodIntermediate, CERT_ATTRB_COLUMN_INTERMEDIATE), "root.config", (String)comboBoxCertHashFuncIntermediate.getSelectedItem());

				generatedCertificateRetStr = generateCertificate(false, "EndEntity", generatedCertificateRetStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTFILE], generatedCertificateRetStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTKEYFILE], (String)tableCertAttributes.getValueAt(0, CERT_ATTRB_COLUMN_END_ENTITY + 1), subjCertAttributes[CERT_ATTRB_COLUMN_END_ENTITY], certGenerateGetKeyMethod(comboBoxCertKeyMethodEndEntity, CERT_ATTRB_COLUMN_END_ENTITY), "intermediate.config", (String)comboBoxCertHashFuncEndEntity.getSelectedItem());
				
				try 
				{
					Thread.sleep(400);

					deleteJunkFilesAtWs();
				} 
				catch (InterruptedException e) 
				{
					e.printStackTrace();
				}
			}
		});
		
		btnGenerateCertificates.setBounds(318, 198, 221, 23);
		
		groupBoxCertGenerate.add(btnGenerateCertificates);
		
		JScrollPane scrollPaneCertAttributes = new JScrollPane();
		scrollPaneCertAttributes.setBounds(12, 43, 820, 93);
		groupBoxCertGenerate.add(scrollPaneCertAttributes);
		
		tableCertAttributes = new JTable();
		scrollPaneCertAttributes.setViewportView(tableCertAttributes);
		tableCertAttributes.setModel(new DefaultTableModel(
			new Object[][] {
				{"Days to Expire", "30", "30", "30"},
				{"Common Name (CN)", "RootCert", "IntermediateCert", "EndEntityCert"},
				{"Organisational Unit (OU)", "", "", ""},
				{"Organisation (O)", "", "", ""},
				{"Locality Name (L)", "UK", "UK", "UK"},
				{"State or Province Name (ST)", "", "", ""},
				{"Country Name (C)", "", "", ""},
				{"Title (T)", "", "", ""},
				{"SERIALNUMBER", "", "", ""},
				{"Given Name (GN)", "", "", ""},
				{"Surname (SN)", "", "", ""},
				{"initials ", "", "", ""},
				{"pseudonym", "", "", ""},
				{"Domain Component (DC)", "", "", ""},
				{"STREET", "", "", ""},
				{"User ID (UID)", "", "", ""},
				{"dnQualifier", "", "", ""},
				{"generationQualifier", "", "", ""},
			},
			new String[] {
				"", "Root Certififcate (CA)", "Intermediate Certificate (CA)", "End Entity Certificate"
			}
		) {
			Class[] columnTypes = new Class[] {
				String.class, String.class, String.class, String.class
			};
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}
			boolean[] columnEditables = new boolean[] {
				false, true, true, true
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		});
		tableCertAttributes.getColumnModel().getColumn(0).setResizable(false);
		tableCertAttributes.getColumnModel().getColumn(0).setPreferredWidth(155);
		tableCertAttributes.getColumnModel().getColumn(1).setPreferredWidth(148);
		tableCertAttributes.getColumnModel().getColumn(2).setPreferredWidth(159);
		tableCertAttributes.getColumnModel().getColumn(3).setPreferredWidth(149);
		
		comboBoxCertKeyMethodRoot.addItemListener(new ItemListener() 
		{
			public void itemStateChanged(ItemEvent arg0) 
			{
				if(comboBoxCertKeyMethodRoot.getSelectedIndex() == COMBO_INDEX_CERT_KEY_METHOD_SELECT_KEY_FILE)
				{
					JFileChooser fileChooser = new JFileChooser();
					
					if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
					{
						certKeyFile[CERT_ATTRB_COLUMN_ROOT] = fileChooser.getSelectedFile().getPath();
						
						textCertStatus.setText(textCertStatus.getText() +  "\n"  +  "[ " + LocalDateTime.now() + " ] --> " + "\"" + certKeyFile[CERT_ATTRB_COLUMN_ROOT]  + "\" selected as key file for Root Certificate generation. \n");
						
						comboBoxCertKeyMethodRoot.setSelectedIndex(COMBO_INDEX_CERT_KEY_METHOD_FILE_SELECTED);
					}	
				}
			}
		});
		
		comboBoxCertKeyMethodIntermediate.addItemListener(new ItemListener() 
		{
			public void itemStateChanged(ItemEvent arg0) 
			{				
				if(comboBoxCertKeyMethodIntermediate.getSelectedIndex() == COMBO_INDEX_CERT_KEY_METHOD_SELECT_KEY_FILE)
				{
					JFileChooser fileChooser = new JFileChooser();
					
					if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
					{
						certKeyFile[CERT_ATTRB_COLUMN_INTERMEDIATE]  = fileChooser.getSelectedFile().getPath();
						
						textCertStatus.setText( textCertStatus.getText() + "\n"  +  "[ " + LocalDateTime.now() + " ] --> " + "\"" + certKeyFile[CERT_ATTRB_COLUMN_INTERMEDIATE]  + "\" selected as key file for Intermediate Certificate generation. \n");

						comboBoxCertKeyMethodIntermediate.setSelectedIndex(COMBO_INDEX_CERT_KEY_METHOD_FILE_SELECTED);
					}	
				}
			}
		});
		
		comboBoxCertKeyMethodEndEntity.addItemListener(new ItemListener() 
		{
			public void itemStateChanged(ItemEvent arg0) 
			{
				if(comboBoxCertKeyMethodEndEntity.getSelectedIndex() == COMBO_INDEX_CERT_KEY_METHOD_SELECT_KEY_FILE)
				{
					JFileChooser fileChooser = new JFileChooser();
					
					if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
					{
						certKeyFile[CERT_ATTRB_COLUMN_END_ENTITY]  = fileChooser.getSelectedFile().getPath();
						
						textCertStatus.setText(textCertStatus.getText() +  "\n"  +  "[ " + LocalDateTime.now() + " ] --> " + "\"" + certKeyFile[CERT_ATTRB_COLUMN_END_ENTITY]  + "\" selected as key file for End Entity Certificate generation. \n");
						
						comboBoxCertKeyMethodEndEntity.setSelectedIndex(COMBO_INDEX_CERT_KEY_METHOD_FILE_SELECTED);
					}	
				}
			}
		});
		
		comboBoxCertKeyMethodRoot.setBounds(232, 144, 165, 18);
		groupBoxCertGenerate.add(comboBoxCertKeyMethodRoot);
		
		comboBoxCertKeyMethodIntermediate.setBounds(439, 144, 165, 18);
		groupBoxCertGenerate.add(comboBoxCertKeyMethodIntermediate);
		
		comboBoxCertKeyMethodEndEntity.setBounds(639, 144, 165, 18);
		groupBoxCertGenerate.add(comboBoxCertKeyMethodEndEntity);
		
		JLabel lblSelectKeyGeneration = new JLabel("Select Key Generation Method:");
		lblSelectKeyGeneration.setFont(new Font("Tahoma", Font.BOLD, 11));
		lblSelectKeyGeneration.setBounds(12, 148, 177, 14);
		groupBoxCertGenerate.add(lblSelectKeyGeneration);
		
		txtCertGenSelectPath = new JTextField();
		txtCertGenSelectPath.setText("Select the path which key, csr and certificate files to be generated");
		txtCertGenSelectPath.setEditable(false);
		txtCertGenSelectPath.setColumns(10);
		txtCertGenSelectPath.setBounds(12, 12, 730, 20);
		groupBoxCertGenerate.add(txtCertGenSelectPath);
		
		JButton btnBrowseCertGenSelectPath = new JButton("Browse");
		btnBrowseCertGenSelectPath.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtCertGenSelectPath.setText(fileChooser.getSelectedFile().getPath());
					certificateWsSelected = true;
					
					String[] tmp = txtCertGenSelectPath.getText().split("\\\\");
					
					CertWSPath1BackSlash = tmp[0];
					CertWSPath2BackSlash = tmp[0];
					CertWSPath4BackSlash = tmp[0];
					
					for(int i=1; i < tmp.length ; i++)
					{
						CertWSPath1BackSlash = CertWSPath1BackSlash + "\\"+ tmp[i];
						CertWSPath2BackSlash = CertWSPath2BackSlash + "\\\\"+ tmp[i];
						CertWSPath4BackSlash = CertWSPath4BackSlash + "\\\\\\\\"+  tmp[i];
					}
				}
			}
		});
		btnBrowseCertGenSelectPath.setBounds(752, 11, 80, 23);
		groupBoxCertGenerate.add(btnBrowseCertGenSelectPath);
		
		JLabel lblSelectHashFunction = new JLabel("Select Hash Function:");
		lblSelectHashFunction.setFont(new Font("Tahoma", Font.BOLD, 11));
		lblSelectHashFunction.setBounds(12, 173, 177, 14);
		groupBoxCertGenerate.add(lblSelectHashFunction);
		
		comboBoxCertHashFuncRoot.setBounds(232, 169, 165, 18);
		groupBoxCertGenerate.add(comboBoxCertHashFuncRoot);

		comboBoxCertHashFuncIntermediate.setBounds(439, 169, 165, 18);
		groupBoxCertGenerate.add(comboBoxCertHashFuncIntermediate);

		comboBoxCertHashFuncEndEntity.setBounds(639, 169, 165, 18);
		groupBoxCertGenerate.add(comboBoxCertHashFuncEndEntity);
		
		JPanel formatConversion = new JPanel();
		tabbedPane.addTab("File Operations", null, formatConversion, null);
		formatConversion.setLayout(null);
		textAreaScrollPaneFC.setBounds(10, 107, 840, 398);
		
		formatConversion.add(textAreaScrollPaneFC);
		
		JTextArea textAreaFC = new JTextArea();
		textAreaScrollPaneFC.setViewportView(textAreaFC);
		
		txtFCSelectInputFile = new JTextField();
		txtFCSelectInputFile.setFont(new Font("Tahoma", Font.BOLD, 11));
		txtFCSelectInputFile.setText("Select Input File");
		txtFCSelectInputFile.setEditable(false);
		txtFCSelectInputFile.setColumns(10);
		txtFCSelectInputFile.setBounds(10, 22, 433, 20);
		formatConversion.add(txtFCSelectInputFile);
		
		JButton btnFCBrowseFileSelect = new JButton("Browse");
		btnFCBrowseFileSelect.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					txtFCSelectInputFile.setText(fileChooser.getSelectedFile().getPath());
					
					FCInputFileSelected = true;
				}
			}
		});
		btnFCBrowseFileSelect.setBounds(453, 21, 86, 23);
		formatConversion.add(btnFCBrowseFileSelect);
		comboFCFileViewFormat.setBounds(549, 21, 301, 22);
		
		formatConversion.add(comboFCFileViewFormat);
		btnFCConvertFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				if(FCInputFileSelected == false)
				{
					textAreaFC.setText("Error: !!! Select the file !!!");
					return;
				}
				
				int fileFormatComboBoxIndex = comboFCFileViewFormat.getSelectedIndex();
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_SELECT_FILE_OPERATION)
				{
					textAreaFC.setText("Error: !!! Select the file Operation !!!");
					return;
				}
				
				String inputFile = "\"" + txtFCSelectInputFile.getText() + "\"";
				String outputFile = "\"" + txtFCSelectInputFile.getText().replace(".", "");
				
				cmdInterpretor.addCommandLineStr("openssl");
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_ASN1 || fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_ASN1)
				{
					cmdInterpretor.addCommandLineStr("asn1parse");
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr(inputFile);
					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_ASN1)
					{
						cmdInterpretor.addCommandLineStr("-inform");
						cmdInterpretor.addCommandLineStr("DER");
					}
					
					textAreaFC.setText(cmdInterpretor.runCommand());
					
					displayCmdInTextAreaAndClear();
					
					return;
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_CERT_FILE || fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_CRL_FILE || fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_RSA_PRIV_KEY_FILE || fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_RSA_PUB_KEY_FILE || fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_PUB_EC_KEY_FILE || fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_PRIV_EC_KEY_FILE)
				{					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_CERT_FILE)
					{
						cmdInterpretor.addCommandLineStr("x509");
					}
					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_CRL_FILE)
					{
						cmdInterpretor.addCommandLineStr("crl");
					}
					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_RSA_PRIV_KEY_FILE)
					{
						cmdInterpretor.addCommandLineStr("rsa");
					}
					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_RSA_PUB_KEY_FILE)
					{
						cmdInterpretor.addCommandLineStr("rsa");
						cmdInterpretor.addCommandLineStr("-pubin");
					}
					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_PUB_EC_KEY_FILE)
					{
						cmdInterpretor.addCommandLineStr("ec");
						cmdInterpretor.addCommandLineStr("-pubin");
					}
					
					if(fileFormatComboBoxIndex == FORMAT_CONVERSION_VIEW_PRIV_EC_KEY_FILE)
					{
						cmdInterpretor.addCommandLineStr("ec");
					}
	
					cmdInterpretor.addCommandLineStr("-in");
					cmdInterpretor.addCommandLineStr(inputFile);
					cmdInterpretor.addCommandLineStr("-text"); 
					cmdInterpretor.addCommandLineStr("-noout");
					
					textAreaFC.setText(cmdInterpretor.runCommand());
					
					displayCmdInTextAreaAndClear();
					
					return;
				}
				
				boolean viewHexStr = false;
								
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_DER_CERT)
				{
					cmdInterpretor.addCommandLineStr("x509");
					cmdInterpretor.addCommandLineStr("-outform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".der" + "\"";
					viewHexStr = true;
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_PEM_CERT)
				{
					cmdInterpretor.addCommandLineStr("x509");
					cmdInterpretor.addCommandLineStr("-inform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".pem" + "\"";
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_DER_CRL)
				{
					cmdInterpretor.addCommandLineStr("crl");
					cmdInterpretor.addCommandLineStr("-outform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".der" + "\"";
					viewHexStr = true;
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_PEM_CRL)
				{
					cmdInterpretor.addCommandLineStr("crl");
					cmdInterpretor.addCommandLineStr("-inform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".pem" + "\"";
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_DER_RSA_PRIV)
				{
					cmdInterpretor.addCommandLineStr("rsa");
					cmdInterpretor.addCommandLineStr("-outform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".der" + "\"";
					viewHexStr = true;
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_PEM_RSA_PRIV)
				{
					cmdInterpretor.addCommandLineStr("rsa");
					cmdInterpretor.addCommandLineStr("-inform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".pem" + "\"";
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_DER_ECC_PRIV)
				{
					cmdInterpretor.addCommandLineStr("ec");
					cmdInterpretor.addCommandLineStr("-outform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".der" + "\"";
					viewHexStr = true;
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_PEM_ECC_PRIV)
				{
					cmdInterpretor.addCommandLineStr("ec");
					cmdInterpretor.addCommandLineStr("-inform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".pem" + "\"";
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_DER_RSA_PUB)
				{
					cmdInterpretor.addCommandLineStr("rsa");
					cmdInterpretor.addCommandLineStr("-pubin");
					cmdInterpretor.addCommandLineStr("-outform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".der" + "\"";
					viewHexStr = true;
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_PEM_RSA_PUB)
				{
					cmdInterpretor.addCommandLineStr("rsa");
					cmdInterpretor.addCommandLineStr("-pubin");
					cmdInterpretor.addCommandLineStr("-inform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".pem" + "\"";
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_PEM_TO_DER_ECC_PUB)
				{
					cmdInterpretor.addCommandLineStr("ec");
					cmdInterpretor.addCommandLineStr("-pubin");
					cmdInterpretor.addCommandLineStr("-outform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".der" + "\"";
					viewHexStr = true;
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_DER_TO_PEM_ECC_PUB)
				{
					cmdInterpretor.addCommandLineStr("ec");
					cmdInterpretor.addCommandLineStr("-pubin");
					cmdInterpretor.addCommandLineStr("-inform");
					cmdInterpretor.addCommandLineStr("der");
					outputFile += ".pem" + "\"";
				}

				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_TEXT_TO_BASE64)
				{
					cmdInterpretor.addCommandLineStr("base64");
					outputFile += ".base64" + "\"";
					viewHexStr = true;
				}
				
				if(fileFormatComboBoxIndex == FORMAT_CONVERSION_CONVERT_BASE64_TO_TEXT)
				{
					cmdInterpretor.addCommandLineStr("base64");
					cmdInterpretor.addCommandLineStr("-d");
					outputFile += ".text" + "\"";
				}
				
				cmdInterpretor.addCommandLineStr("-in");
				cmdInterpretor.addCommandLineStr(inputFile);
				cmdInterpretor.addCommandLineStr("-out");
				cmdInterpretor.addCommandLineStr(outputFile);
									
				String cmdRetStr = cmdInterpretor.runCommand();
								
				if(cmdRetStr.compareTo("") != 0 && cmdRetStr.length() > 50 )
				{
					textAreaFC.setText(cmdRetStr);
				}
				else
				{
					textAreaFC.setText("Conversion Completed, \"" + outputFile.split("\\\\")[ outputFile.split("\\\\").length - 1] + " file generated in same path ...");
				}
				
				displayCmdInTextAreaAndClear();
				
				if(viewHexStr == true)
				{
					String[] tmp =  (outputFile.replaceAll("\"","")).split("\\\\");
					
					String FCPathBackSlash = tmp[0];
					
					for(int i=1; i < tmp.length ; i++)
					{
						FCPathBackSlash = FCPathBackSlash + "\\"+ tmp[i];
					}
					
					textAreaFC.setText(textAreaFC.getText() + "\n\n" + "Hex Representation of file content:" + "\n");

					try 
					{
						FileReader reader = new FileReader(FCPathBackSlash);
						
						StringBuilder hexString = new StringBuilder("");
						int ch, cntr = 1;
						
						while((ch = reader.read())!=-1)
						{	
							hexString.append("0x" + Integer.toHexString((Integer)ch) + " ");
							
							if( cntr % 16 == 0)
								hexString.append("\n");
							
							cntr++;
						}
						
						textAreaFC.setText(textAreaFC.getText() + "\n"+ hexString.toString());
					
						reader.close();
					} 
					catch (IOException e) 
					{
						e.printStackTrace();
					}
				}
			}
		});
		
		btnFCConvertFile.setBounds(308, 65, 249, 31);
		
		formatConversion.add(btnFCConvertFile);
		
		JPanel crcNumbers = new JPanel();
		tabbedPane.addTab("CRC&Numbers", null, crcNumbers, null);
		crcNumbers.setLayout(null);
		
		JPanel groupBoxPrimeNumberGenerate = new JPanel();
		groupBoxPrimeNumberGenerate.setLayout(null);
		groupBoxPrimeNumberGenerate.setToolTipText("Output of Encryption");
		groupBoxPrimeNumberGenerate.setName("");
		groupBoxPrimeNumberGenerate.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxPrimeNumberGenerate.setBounds(10, 11, 840, 152);
		crcNumbers.add(groupBoxPrimeNumberGenerate);
		
		btnGeneratePrime = new JButton("Generate Prime Number");
		btnGeneratePrime.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				cmdInterpretor.addCommandLineStr("openssl"); 
				cmdInterpretor.addCommandLineStr("prime");
				cmdInterpretor.addCommandLineStr("-generate");
				cmdInterpretor.addCommandLineStr("-bits");
				cmdInterpretor.addCommandLineStr(textFieldPrimeNumOFBits.getText());
				
				if(chckboxPrimeHexOutput.isSelected())
				{
					cmdInterpretor.addCommandLineStr("-hex");
				}
				
				if(chckboxSafePrime.isSelected())
				{
					cmdInterpretor.addCommandLineStr("-safe");
					textPrimeNumber.setText(textPrimeNumber.getText() + "Save Mode ON: Generated number minus 1 divided by 2 is also prime \n");
				}
				
				textPrimeNumber.setText(textPrimeNumber.getText() + cmdInterpretor.runCommand());
				
				displayCmdInTextAreaAndClear();
			}
		});
		
		btnGeneratePrime.setBounds(329, 123, 184, 23);
		groupBoxPrimeNumberGenerate.add(btnGeneratePrime);
		
		chckboxPrimeHexOutput = new JCheckBox("Hex Output");
		chckboxPrimeHexOutput.setBounds(388, 2, 92, 23);
		groupBoxPrimeNumberGenerate.add(chckboxPrimeHexOutput);
		
		chckboxSafePrime = new JCheckBox("Safe Prime");
		chckboxSafePrime.setBounds(262, 2, 92, 23);
		groupBoxPrimeNumberGenerate.add(chckboxSafePrime);
		
		textFieldPrimeNumOFBits = new JTextField();
		textFieldPrimeNumOFBits.setBounds(137, 6, 96, 20);
		groupBoxPrimeNumberGenerate.add(textFieldPrimeNumOFBits);
		textFieldPrimeNumOFBits.setColumns(10);
		
		JLabel lblNewLabel = new JLabel("Number of Bits:");
		lblNewLabel.setBounds(10, 6, 107, 14);
		groupBoxPrimeNumberGenerate.add(lblNewLabel);
		
		JScrollPane scrollPane_6 = new JScrollPane();
		scrollPane_6.setBounds(10, 32, 820, 84);
		groupBoxPrimeNumberGenerate.add(scrollPane_6);
		
		textPrimeNumber = new JTextArea();
		scrollPane_6.setViewportView(textPrimeNumber);
		
		JPanel groupBoxPrimeNumberGenerate_1 = new JPanel();
		groupBoxPrimeNumberGenerate_1.setLayout(null);
		groupBoxPrimeNumberGenerate_1.setToolTipText("Output of Encryption");
		groupBoxPrimeNumberGenerate_1.setName("");
		groupBoxPrimeNumberGenerate_1.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		groupBoxPrimeNumberGenerate_1.setBounds(10, 174, 840, 331);
		crcNumbers.add(groupBoxPrimeNumberGenerate_1);
		
		Parameters [][] CrcPredefinedParams = new Parameters[4][24];
		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][0] 	= CRC.Parameters.CRC8_IEEE;		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][1] 	= CRC.Parameters.CRC8_SAE_J1850;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][2] 	= CRC.Parameters.CRC8_SAE_J1850_ZERO;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][3] 	= CRC.Parameters.CRC8_8H2F;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][4] 	= CRC.Parameters.CRC8_CDMA2000;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][5] 	= CRC.Parameters.CRC8_DARC;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][6] 	= CRC.Parameters.CRC8_DVB_S2;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][7] 	= CRC.Parameters.CRC8_EBU;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][8] 	= CRC.Parameters.CRC8_ICODE;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][9] 	= CRC.Parameters.CRC8_ITU;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][10] = CRC.Parameters.CRC8_MAXIM;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][11] = CRC.Parameters.CRC8_ROHC;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC8][12] = CRC.Parameters.CRC8_WCDMA;
		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][0]	 = CRC.Parameters.CRC16_CCITT_ZERO;		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][1]	 = CRC.Parameters.CRC16_ARC;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][2]	 = CRC.Parameters.CRC16_AUG_CCITT;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][3]	 = CRC.Parameters.CRC16_BUYPASS;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][4]	 = CRC.Parameters.CRC16_CCITT_FALSE;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][5]	 = CRC.Parameters.CRC16_CDMA2000;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][6]	 = CRC.Parameters.CRC16_DDS_110;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][7]	 = CRC.Parameters.CRC16_DECT_R;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][8]	 = CRC.Parameters.CRC16_DECT_X;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][9]  = CRC.Parameters.CRC16_DNP;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][10] = CRC.Parameters.CRC16_EN_13757;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][11] = CRC.Parameters.CRC16_GENIBUS;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][12] = CRC.Parameters.CRC16_MAXIM;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][13] = CRC.Parameters.CRC16_MCRF4XX;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][14] = CRC.Parameters.CRC16_RIELLO;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][15] = CRC.Parameters.CRC16_T10_DIF;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][16] = CRC.Parameters.CRC16_TELEDISK;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][17] = CRC.Parameters.CRC16_TMS37157;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][18] = CRC.Parameters.CRC16_USB;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][19] = CRC.Parameters.CRC16_A;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][20] = CRC.Parameters.CRC16_KERMIT;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][21] = CRC.Parameters.CRC16_MODBUS;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][22] = CRC.Parameters.CRC16_X_25;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC16][23] = CRC.Parameters.CRC16_XMODEM;
		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][0]	 = CRC.Parameters.CRC32_CRC32;		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][1]	 = CRC.Parameters.CRC32_BZIP2;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][2]	 = CRC.Parameters.CRC32_C;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][3]	 = CRC.Parameters.CRC32_D;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][4]	 = CRC.Parameters.CRC32_MPEG2;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][5]	 = CRC.Parameters.CRC32_POSIX;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][6]	 = CRC.Parameters.CRC32_Q;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][7]	 = CRC.Parameters.CRC32_JAMCRC;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC32][8]	 = CRC.Parameters.CRC32_XFER;
		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC64][0]	 = CRC.Parameters.CRC64_ECMA_182;		
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC64][1]	 = CRC.Parameters.CRC64_GO_ISO;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC64][2]	 = CRC.Parameters.CRC64_WE;
		CrcPredefinedParams[CRC_PREDEFINED_PARAMS_CRC64][3]	 = CRC.Parameters.CRC64_XZ;
		
		JButton btnGenerateCRC = new JButton("Generate CRC");
		btnGenerateCRC.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				int 			width = 8;   
				long 			polynomial; 
				boolean 		reflectIn;   
				boolean 		reflectOut;   
				long 			init; 
				long 			finalXor; 
				byte [] 		fileBytes = null;
				StringBuilder 	fileString = new StringBuilder("");
				
				if(isCRCFileInputAssigned == true)
				{
					try 
					{
						FileReader CRCInputFileReader = new FileReader((new File(textFieldCRCFileInput.getText())));
						int ch;
						
						while((ch = CRCInputFileReader.read())!=-1)
						{	
							fileString.append(Character.toString(ch));
						}
						
						fileBytes = fileString.toString().getBytes();
						
						CRCInputFileReader.close();
					} 
					catch (FileNotFoundException e1) 
					{
						e1.printStackTrace();
					} 
					catch (IOException e1) 
					{
						e1.printStackTrace();
					}
				}
				
				if(rdbtnCRC8.isSelected())
				{
					width = 8;
				}
				
				if(rdbtnCRC16.isSelected())
				{
					width = 16;
				}
				
				if(rdbtnCRC32.isSelected())
				{
					width = 32;
				}
				
				if(rdbtnCRC64.isSelected())
				{
					width = 64;
				}
				
				polynomial = (new BigInteger(textFieldCRCPolynomial.getText().replaceAll("0x", ""), 16)).longValue();
				finalXor = (new BigInteger(textFieldCRCXorValue.getText().replaceAll("0x", ""), 16)).longValue();
				init = (new BigInteger(textFieldCRCInit.getText().replaceAll("0x", ""), 16)).longValue(); 
				
				reflectIn = chckbxCRCReflectInput.isSelected();
				reflectOut = chckbxCRCReflectResult.isSelected();
				
				Parameters params = new Parameters(width , polynomial, init, reflectIn, reflectOut, finalXor);
				
				CRC crc = new CRC(params);
				
				long [] crcTable = crc.getCrcTable();
				
				if (textCRCInput.getText().length() != 0)
				{
					textCRCOutput.setText("CRC Text Result:  " + "0x" + Long.toHexString( CRC.calculateCRC(params, textCRCInput.getText().getBytes())).toUpperCase() + "\n\n" );
				}
				
				if (fileBytes != null)
				{
					textCRCOutput.setText(textCRCOutput.getText() + "CRC File Result:  " + "0x" + Long.toHexString( CRC.calculateCRC(params, fileBytes)).toUpperCase() + "\n\n" );
				}
				
				textCRCOutput.setText(textCRCOutput.getText() + "CRC Table:\n");
						
				for(int i = 0; i < crcTable.length; i++)
				{
					textCRCOutput.setText(textCRCOutput.getText() + "0x" + Long.toHexString(crcTable[i]).toUpperCase() + " ");
					
					if((i + 1) %8 == 0)
					{
						textCRCOutput.setText(textCRCOutput.getText() + "\n");
					}
				}
			}
		});
		
		comboCRCPredifened.addItemListener(new ItemListener() 
		{
			public void itemStateChanged(ItemEvent e) 
			{
				int comboIndex = comboCRCPredifened.getSelectedIndex();
				int crcSizeIndex = 0; 
				
				if(comboIndex < 0)
				{
					comboIndex = 0;
				}
					
				if(rdbtnCRC8.isSelected())
				{
					crcSizeIndex = CRC_PREDEFINED_PARAMS_CRC8;
				}
				
				if(rdbtnCRC16.isSelected())
				{
					crcSizeIndex = CRC_PREDEFINED_PARAMS_CRC16;
				}
				
				if(rdbtnCRC32.isSelected())
				{
					crcSizeIndex = CRC_PREDEFINED_PARAMS_CRC32;
				}
				
				if(rdbtnCRC64.isSelected())
				{
					crcSizeIndex = CRC_PREDEFINED_PARAMS_CRC64;
				}
				
				String polynomial = "0x" + Long.toHexString(CrcPredefinedParams[crcSizeIndex][comboIndex].getPolynomial()).toUpperCase();
				String init = "0x" + Long.toHexString(CrcPredefinedParams[crcSizeIndex][comboIndex].getInit()).toUpperCase();
				String finalXorValue = "0x" + Long.toHexString(CrcPredefinedParams[crcSizeIndex][comboIndex].getFinalXor()).toUpperCase();
				
				if(crcSizeIndex == CRC_PREDEFINED_PARAMS_CRC32)
				{
					polynomial = polynomial.replaceAll("0xFFFFFFFF", "0x");
					init = init.replaceAll("0xFFFFFFFF", "0x");
					finalXorValue = finalXorValue.replaceAll("0xFFFFFFFF", "0x");
				}
				
				textFieldCRCPolynomial.setText(polynomial);
				textFieldCRCInit.setText(init);
				textFieldCRCXorValue.setText(finalXorValue);
				
				chckbxCRCReflectInput.setSelected(CrcPredefinedParams[crcSizeIndex][comboIndex].isReflectIn());
				chckbxCRCReflectResult.setSelected(CrcPredefinedParams[crcSizeIndex][comboIndex].isReflectOut());
			}
		});
		
		comboCRCPredifened.addItem("CRC 8");
		comboCRCPredifened.addItem("SAE J1850");
		comboCRCPredifened.addItem("SAE J1850 ZERO");
		comboCRCPredifened.addItem("8H2F");
		comboCRCPredifened.addItem("CDMA2000");
		comboCRCPredifened.addItem("DARC");
		comboCRCPredifened.addItem("DVB S2");
		comboCRCPredifened.addItem("EBU");
		comboCRCPredifened.addItem("ICODE");
		comboCRCPredifened.addItem("ITU");
		comboCRCPredifened.addItem("MAXIM");
		comboCRCPredifened.addItem("ROHC");
		comboCRCPredifened.addItem("WCDMA");
		
		btnGenerateCRC.setBounds(321, 153, 184, 29);
		groupBoxPrimeNumberGenerate_1.add(btnGenerateCRC);

		rdbtnCRC8.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				comboCRCPredifened.removeAllItems();
				
				comboCRCPredifened.addItem("CRC 8");
				comboCRCPredifened.addItem("SAE J1850");
				comboCRCPredifened.addItem("SAE J1850 ZERO");
				comboCRCPredifened.addItem("8H2F");
				comboCRCPredifened.addItem("CDMA2000");
				comboCRCPredifened.addItem("DARC");
				comboCRCPredifened.addItem("DVB S2");
				comboCRCPredifened.addItem("EBU");
				comboCRCPredifened.addItem("ICODE");
				comboCRCPredifened.addItem("ITU");
				comboCRCPredifened.addItem("MAXIM");
				comboCRCPredifened.addItem("ROHC");
				comboCRCPredifened.addItem("WCDMA");
			}
		});
		buttonGroupCRC.add(rdbtnCRC8);
		rdbtnCRC8.setSelected(true);
		rdbtnCRC8.setBounds(10, 7, 64, 23);
		groupBoxPrimeNumberGenerate_1.add(rdbtnCRC8);
		
		rdbtnCRC16.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				comboCRCPredifened.removeAllItems();
				
				comboCRCPredifened.addItem("CCITT ZERO");
				comboCRCPredifened.addItem("ARC");
				comboCRCPredifened.addItem("AUG CCITT");
				comboCRCPredifened.addItem("BUYPASS");
				comboCRCPredifened.addItem("CCITT FALSE");
				comboCRCPredifened.addItem("CDMA2000");
				comboCRCPredifened.addItem("DDS 110");
				comboCRCPredifened.addItem("DECT R");
				comboCRCPredifened.addItem("DECT X");
				comboCRCPredifened.addItem("DNP");
				comboCRCPredifened.addItem("EN13757");
				comboCRCPredifened.addItem("GENIBUS");
				comboCRCPredifened.addItem("MAXIM");
				comboCRCPredifened.addItem("MCRF4XX");
				comboCRCPredifened.addItem("RIELLO");
				comboCRCPredifened.addItem("T10 DIF");
				comboCRCPredifened.addItem("TELEDISK");
				comboCRCPredifened.addItem("TMS37157");
				comboCRCPredifened.addItem("USB");
				comboCRCPredifened.addItem("A");
				comboCRCPredifened.addItem("KERMIT");
				comboCRCPredifened.addItem("MODBUS");
				comboCRCPredifened.addItem("X 25");
				comboCRCPredifened.addItem("X MODEM");
			}
		});
		buttonGroupCRC.add(rdbtnCRC16);
		rdbtnCRC16.setBounds(90, 7, 74, 23);
		groupBoxPrimeNumberGenerate_1.add(rdbtnCRC16);
		
		rdbtnCRC32.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				comboCRCPredifened.removeAllItems();
				
				comboCRCPredifened.addItem("CRC32 IEEE");
				comboCRCPredifened.addItem("BZIP2");
				comboCRCPredifened.addItem("C");
				comboCRCPredifened.addItem("D");
				comboCRCPredifened.addItem("MPEG2");
				comboCRCPredifened.addItem("POSIX");
				comboCRCPredifened.addItem("Q");
				comboCRCPredifened.addItem("JAMCRC");
				comboCRCPredifened.addItem("XFER");
			}
		});
		buttonGroupCRC.add(rdbtnCRC32);
		rdbtnCRC32.setBounds(181, 7, 84, 23);
		groupBoxPrimeNumberGenerate_1.add(rdbtnCRC32);
		buttonGroupCRC.add(rdbtnCRC64);
		rdbtnCRC64.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				comboCRCPredifened.removeAllItems();
				
				comboCRCPredifened.addItem("ECMA 182");
				comboCRCPredifened.addItem("GO ISO");
				comboCRCPredifened.addItem("WE");
				comboCRCPredifened.addItem("XZ");
			}
		});
		rdbtnCRC64.setBounds(267, 7, 74, 23);
		
		groupBoxPrimeNumberGenerate_1.add(rdbtnCRC64);
		comboCRCPredifened.setBounds(441, 7, 104, 22);
		
		groupBoxPrimeNumberGenerate_1.add(comboCRCPredifened);
		lblPredefinedParameters.setBounds(347, 12, 84, 14);
		
		groupBoxPrimeNumberGenerate_1.add(lblPredefinedParameters);
		
		chckbxCRCReflectInput.setBounds(589, 7, 104, 23);
		groupBoxPrimeNumberGenerate_1.add(chckbxCRCReflectInput);
		
		chckbxCRCReflectResult.setBounds(716, 7, 112, 23);
		groupBoxPrimeNumberGenerate_1.add(chckbxCRCReflectResult);
		
		JLabel lblCRCPolynomial = new JLabel("Polynomial (Hex):");
		lblCRCPolynomial.setBounds(10, 40, 112, 14);
		groupBoxPrimeNumberGenerate_1.add(lblCRCPolynomial);

		textFieldCRCPolynomial.setColumns(10);
		textFieldCRCPolynomial.setBounds(118, 37, 147, 20);
		groupBoxPrimeNumberGenerate_1.add(textFieldCRCPolynomial);
		
		JScrollPane scrollPane_8 = new JScrollPane();
		scrollPane_8.setBounds(10, 189, 820, 131);
		groupBoxPrimeNumberGenerate_1.add(scrollPane_8);
		scrollPane_8.setViewportView(textCRCOutput);
		lblCRCInitValue.setBounds(10, 68, 112, 14);
		
		groupBoxPrimeNumberGenerate_1.add(lblCRCInitValue);
		textFieldCRCInit.setColumns(10);
		textFieldCRCInit.setBounds(118, 65, 147, 20);
		
		groupBoxPrimeNumberGenerate_1.add(textFieldCRCInit);
		lblCRCXOR.setBounds(10, 96, 112, 14);
		
		groupBoxPrimeNumberGenerate_1.add(lblCRCXOR);
		textFieldCRCXorValue.setColumns(10);
		textFieldCRCXorValue.setBounds(118, 93, 147, 20);
		
		groupBoxPrimeNumberGenerate_1.add(textFieldCRCXorValue);
		
		JButton btnBrowseCRCFile = new JButton("Browse");
		btnBrowseCRCFile.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent e) 
			{
				JFileChooser fileChooser = new JFileChooser();
				
				if(fileChooser.showOpenDialog(selfInstance) == JFileChooser.APPROVE_OPTION)
				{
					isCRCFileInputAssigned = true;
					
					textFieldCRCFileInput.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btnBrowseCRCFile.setBounds(750, 121, 80, 23);
		groupBoxPrimeNumberGenerate_1.add(btnBrowseCRCFile);
		
		textFieldCRCFileInput = new JTextField();
		textFieldCRCFileInput.setText("Select the file to  generate CRC");
		textFieldCRCFileInput.setEditable(false);
		textFieldCRCFileInput.setColumns(10);
		textFieldCRCFileInput.setBounds(10, 122, 730, 20);
		groupBoxPrimeNumberGenerate_1.add(textFieldCRCFileInput);
		
		JScrollPane scrollPane_7 = new JScrollPane();
		scrollPane_7.setBounds(277, 35, 551, 78);
		groupBoxPrimeNumberGenerate_1.add(scrollPane_7);
		
		scrollPane_7.setViewportView(textCRCInput);
		
		JLabel lblCRCResult = new JLabel("CRC Result and CRC Table:");
		lblCRCResult.setBounds(10, 172, 194, 14);
		groupBoxPrimeNumberGenerate_1.add(lblCRCResult);
		
		comboBoxCertKeyMethodRoot.addItem("RSA 1024");
		comboBoxCertKeyMethodRoot.addItem("RSA 2048");
		comboBoxCertKeyMethodRoot.addItem("RSA 4096");
		comboBoxCertKeyMethodRoot.addItem("Select Key file");
		comboBoxCertKeyMethodRoot.addItem("File Selected");
		
		comboBoxCertKeyMethodIntermediate.addItem("RSA 1024");
		comboBoxCertKeyMethodIntermediate.addItem("RSA 2048");
		comboBoxCertKeyMethodIntermediate.addItem("RSA 4096");
		comboBoxCertKeyMethodIntermediate.addItem("Select Key file");
		comboBoxCertKeyMethodIntermediate.addItem("File Selected");
		
		comboBoxCertKeyMethodEndEntity.addItem("RSA 1024");
		comboBoxCertKeyMethodEndEntity.addItem("RSA 2048");
		comboBoxCertKeyMethodEndEntity.addItem("RSA 4096");
		comboBoxCertKeyMethodEndEntity.addItem("Select Key file");
		comboBoxCertKeyMethodEndEntity.addItem("File Selected");
		scrollPaneOpenSslCmd.setBounds(10, 563, 865, 97);
		
		mainPane.add(scrollPaneOpenSslCmd);
		btnClearCmdTextArea.addMouseListener(new MouseAdapter() 
		{
			@Override
			public void mouseClicked(MouseEvent arg0) 
			{
				textAreaOpenSslCmd.setText(null);
			}
		});
		
		btnClearCmdTextArea.setBounds(10, 664, 865, 20);
		
		mainPane.add(btnClearCmdTextArea);
		
		/* *** add list of Elliptic Curve Names to combo box Start *** */
		
		cmdInterpretor.addCommandLineStr("openssl"); 
		cmdInterpretor.addCommandLineStr("ecparam");
		cmdInterpretor.addCommandLineStr("-list_curves");
		
		String [] ecnames = cmdInterpretor.runCommand().split("\n");
		
		displayCmdInTextAreaAndClear();
		
		for(int i = 0; i < ecnames.length; i++)
		{			
			if(ecnames[i].contains(":") == true)
			{
				comboKeyGenElipticCurveName.addItem(ecnames[i].split(":")[0].replace(" " , ""));
			}
		}
		
		/* *** add list of Elliptic Curve Names to combo box End *** */
	}

	protected boolean ispasswordLenghtOk() 
	{
		int		passwdLen = 8;
		String	cipherName = (String)comboEncryptCiphersCmac.getSelectedItem();
		
		if(cipherName.contains("128") || cipherName.contains("des-ede-cbc") || cipherName.contains("idea-cbc")  || cipherName.contains("seed-cbc") || cipherName.contains("sm4-cbc"))
		{
			passwdLen = 16;
		}
		
		if(cipherName.contains("192") || cipherName.contains("des-ede3-cbc") || cipherName.contains("desx-cb"))
		{
			passwdLen = 24;
		}
		
		if(cipherName.contains("256"))
		{
			passwdLen = 32;
		}

		if(passwordFieldMac.getPassword().length == passwdLen)
		{
			return true;
		}
		
		lblHashStatusBox.setText("!!! Password length should be " + passwdLen + " !!!");
		
		return false;
	}

	protected void deleteJunkFilesAtWs() 
	{
		cmdInterpretor.addCommandLineStr("del"); 
		cmdInterpretor.addCommandLineStr("\"" + CertWSPath1BackSlash  + "\\*serial*\"");
		cmdInterpretor.addCommandLineStr("\"" + CertWSPath1BackSlash  + "\\*index*\"");
		cmdInterpretor.addCommandLineStr("\"" + CertWSPath1BackSlash  + "\\*old*\"");
		cmdInterpretor.addCommandLineStr("\"" + CertWSPath1BackSlash  + "\\*attr*\"");
		cmdInterpretor.addCommandLineStr("\"" + CertWSPath1BackSlash  + "\\*0*\"");
		cmdInterpretor.runCommand();
		
		displayCmdInTextAreaAndClear();
	}

	protected void generateConfigFilesToWs() 
	{		
		String rootIndexFile = CertWSPath2BackSlash  + "\\\\rootindex"; 
		String rootSerialFile = CertWSPath2BackSlash  + "\\\\rootserial"; 
		String intermediateIndexFile = CertWSPath2BackSlash  + "\\\\intermediateindex"; 
		String intermediateSerialFile =  CertWSPath2BackSlash  + "\\\\intermediateserial"; 
		String rootConfigFile = CertWSPath2BackSlash  + "\\\\root.config"; 
		String intermediateConfigFile = CertWSPath2BackSlash  + "\\\\intermediate.config"; 
		
		File rootIndex = new File(rootIndexFile);
		File rootSerial = new File(rootSerialFile);
		File intermediateIndex = new File(intermediateIndexFile);
		File intermediateSerial = new File(intermediateSerialFile);
		File rootConfig = new File(rootConfigFile);
		File intermediateConfig = new File(intermediateConfigFile);
		
		try 
		{	
			rootIndex.createNewFile();
			rootSerial.createNewFile();
			intermediateIndex.createNewFile();
			intermediateSerial.createNewFile();
			rootConfig.createNewFile();
			intermediateConfig.createNewFile();
			
			FileWriter rootIndexWriter = new FileWriter(rootIndexFile);
			FileWriter rootSerialWriter = new FileWriter(rootSerialFile);
			FileWriter intermediateIndexWriter = new FileWriter(intermediateIndexFile);
			FileWriter intermediateSerialWriter = new FileWriter(intermediateSerialFile);
			FileWriter rootConfigWriter = new FileWriter(rootConfigFile);
			FileWriter intermediateConfigWriter = new FileWriter(intermediateConfigFile);
			
			rootIndexWriter.write("[empty]");
			rootIndexWriter.close();
			
			rootSerialWriter.write("00");
			rootSerialWriter.close();
			
			intermediateIndexWriter.write("[empty]");
			intermediateIndexWriter.close();
			
			intermediateSerialWriter.write("00");
			intermediateSerialWriter.close();
			
			String policyAndExtStr = "[ policy_any ]\r\n"
					+ "commonName             = supplied\r\n"
					+ "countryName            = optional\r\n"
					+ "stateOrProvinceName    = optional\r\n"
					+ "organizationName       = optional\r\n"
					+ "organizationalUnitName = optional\r\n"
					+ "localityName		   	  = optional\r\n"
					+ "title		          = optional\r\n"
					+ "serialNumber           = optional\r\n"
					+ "givenName              = optional\r\n"
					+ "surname                = optional\r\n"
					+ "initials               = optional\r\n"
					+ "pseudonym              = optional\r\n"
					+ "street                 = optional\r\n"
					+ "userId                 = optional\r\n"
					+ "dnQualifier            = optional\r\n"
					+ "generationQualifier    = optional\r\n"
					+ "domainComponent        = optional\r\n"
					+ "\r\n"
					+ "[ v3_ext ]\r\n"
					+ "basicConstraints = critical,CA:true\r\n"
					+ "keyUsage         = critical,keyCertSign";
			
			rootConfigWriter.write("[ CA_default]\r\n"
					+ "database        = \"" + CertWSPath4BackSlash + "\\\\rootindex\"\r\n"
					+ "serial          = \"" + CertWSPath4BackSlash + "\\\\rootserial\"\r\n"
					+ "\r\n"
					+ policyAndExtStr);
			
			rootConfigWriter.close();
			
			intermediateConfigWriter.write("[ CA_default]\r\n"
					+ "database        = \"" + CertWSPath4BackSlash + "\\\\intermediateindex\"\r\n"
					+ "serial          = \"" + CertWSPath4BackSlash + "\\\\intermediateserial\"\r\n"
					+ "\r\n"
					+ policyAndExtStr);
			
			intermediateConfigWriter.close();	
		} 
		
		catch (IOException e) 
		{
			e.printStackTrace();
		}
	}

	protected String[] generateCertificate(boolean isSelfSigned, String certificateName, String CACertFile, String CAKeyFile, String daysToExpire, String subjectAttribute, String[] keyMethod, String configFile, String hashMethod) 
	{
			String[] retStr = {"", "", "", ""};
			
			String certificateFilesPath = txtCertGenSelectPath.getText();
			String csrFileName = "\"" + certificateFilesPath + "\\"  + certificateName + ".csr" + "\""; 
			String keyFileName = "";
			String certFileName = "\"" + certificateFilesPath + "\\"  + certificateName + ".pem" + "\"";
			String configFileName = "\"" + certificateFilesPath + "\\" + configFile + "\"";

			cmdInterpretor.addCommandLineStr("openssl"); 
			cmdInterpretor.addCommandLineStr("req");
			
			if(keyMethod[0].compareTo("FILE") == 0)
			{
				keyFileName = "\"" + keyMethod[1] + "\"";
				
				cmdInterpretor.addCommandLineStr("-new");
				cmdInterpretor.addCommandLineStr("-key");
				cmdInterpretor.addCommandLineStr(keyFileName);
			}
			
			if(keyMethod[0].compareTo("RSA") == 0)
			{
				keyFileName = "\"" + certificateFilesPath  + "\\" + certificateName + ".key" + "\"";
				
				cmdInterpretor.addCommandLineStr("-newkey");
				cmdInterpretor.addCommandLineStr("rsa:" + keyMethod[1]); 
				cmdInterpretor.addCommandLineStr("-nodes");
				cmdInterpretor.addCommandLineStr("-keyout");
				cmdInterpretor.addCommandLineStr(keyFileName);
			}
			
			cmdInterpretor.addCommandLineStr("-out");
			cmdInterpretor.addCommandLineStr(csrFileName);
			
			cmdInterpretor.addCommandLineStr(subjectAttribute); 
			
			retStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CMD_RET] = cmdInterpretor.runCommand();
			
			displayCmdInTextAreaAndClear();
			
			if(isSelfSigned)
			{
				CACertFile = certFileName;
				CAKeyFile  = keyFileName;
			}

			cmdInterpretor.addCommandLineStr("openssl"); 
			cmdInterpretor.addCommandLineStr("ca");
			cmdInterpretor.addCommandLineStr("-in"); 
			cmdInterpretor.addCommandLineStr(csrFileName);
			cmdInterpretor.addCommandLineStr("-out"); 
			cmdInterpretor.addCommandLineStr(certFileName);
			cmdInterpretor.addCommandLineStr("-extensions"); 
			cmdInterpretor.addCommandLineStr("v3_ext");
			cmdInterpretor.addCommandLineStr("-days"); 
			cmdInterpretor.addCommandLineStr(daysToExpire);
			cmdInterpretor.addCommandLineStr("-cert"); 
			cmdInterpretor.addCommandLineStr(CACertFile);
			cmdInterpretor.addCommandLineStr("-keyfile"); 
			cmdInterpretor.addCommandLineStr(CAKeyFile);
			cmdInterpretor.addCommandLineStr("-name"); 
			cmdInterpretor.addCommandLineStr("CA_default");
			cmdInterpretor.addCommandLineStr("-policy"); 
			cmdInterpretor.addCommandLineStr("policy_any");
			cmdInterpretor.addCommandLineStr("-outdir"); 
			cmdInterpretor.addCommandLineStr("\"" + certificateFilesPath + "\"");
			cmdInterpretor.addCommandLineStr("-config");
			cmdInterpretor.addCommandLineStr(configFileName);
			cmdInterpretor.addCommandLineStr("-md");
			cmdInterpretor.addCommandLineStr(hashMethod);
			
			if(isSelfSigned)
			{
				cmdInterpretor.addCommandLineStr("-selfsign");
			}
			
			retStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CMD_RET] += "\n" + cmdInterpretor.runAndConfirmCommand();
			
			displayCmdInTextAreaAndClear();
			
			retStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTCSRFILE] = csrFileName;
			retStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTKEYFILE] = keyFileName;
			retStr[GENERATE_CERTIFICATE_RET_STR_INDEX_CERTFILE] = certFileName;
			
			return retStr;
	}

	private String [] certGenerateCreateSubjectAttribsInStr() 
	{
		String subjCertAttributes[] = {"-subj \"", "-subj \"", "-subj \""};
	
		int minLength = subjCertAttributes[CERT_ATTRB_COLUMN_ROOT].length() + 1;
				
		for(int i = 0; i < subjAttribsCertStr.length; i++)
		{
			if(((String)tableCertAttributes.getValueAt(i + 1, CERT_ATTRB_COLUMN_ROOT + 1)).compareTo("") != 0)
			{
				subjCertAttributes[CERT_ATTRB_COLUMN_ROOT] += "/" + subjAttribsCertStr[i] + "=" + (String)tableCertAttributes.getValueAt(i + 1, CERT_ATTRB_COLUMN_ROOT + 1);
			}
			
			if(((String)tableCertAttributes.getValueAt(i + 1, CERT_ATTRB_COLUMN_INTERMEDIATE + 1)).compareTo("") != 0)
			{
				subjCertAttributes[CERT_ATTRB_COLUMN_INTERMEDIATE] += "/" + subjAttribsCertStr[i] + "=" + (String)tableCertAttributes.getValueAt(i + 1, CERT_ATTRB_COLUMN_INTERMEDIATE + 1);
			}
			
			if(((String)tableCertAttributes.getValueAt(i + 1, CERT_ATTRB_COLUMN_END_ENTITY + 1)).compareTo("") != 0)
			{
				subjCertAttributes[CERT_ATTRB_COLUMN_END_ENTITY] += "/" + subjAttribsCertStr[i] + "=" + (String)tableCertAttributes.getValueAt(i + 1, CERT_ATTRB_COLUMN_END_ENTITY + 1);
			}
		}
			
		subjCertAttributes[CERT_ATTRB_COLUMN_ROOT] += "\"";
		subjCertAttributes[CERT_ATTRB_COLUMN_INTERMEDIATE] += "\"";
		subjCertAttributes[CERT_ATTRB_COLUMN_END_ENTITY] += "\"";
		
		if(subjCertAttributes[CERT_ATTRB_COLUMN_ROOT].length() <= minLength)
		{
			subjCertAttributes[CERT_ATTRB_COLUMN_ROOT] = "";
		}
		
		if(subjCertAttributes[CERT_ATTRB_COLUMN_INTERMEDIATE].length() <= minLength)
		{
			subjCertAttributes[CERT_ATTRB_COLUMN_INTERMEDIATE] = "";
		}
		
		if(subjCertAttributes[CERT_ATTRB_COLUMN_END_ENTITY].length() <= minLength)
		{
			subjCertAttributes[CERT_ATTRB_COLUMN_END_ENTITY] = "";
		}
		
		return  subjCertAttributes;
	}
	
	String [] certGenerateGetKeyMethod(JComboBox<String> combo, int index)
	{
		String [] retStr = {"", ""};
		
		switch(combo.getSelectedIndex())
		{
			case COMBO_INDEX_CERT_KEY_METHOD_RSA_1024:
				retStr[0] = "RSA";
				retStr[1] = "1024";
				break;
				
			case COMBO_INDEX_CERT_KEY_METHOD_RSA_2048:
				retStr[0] = "RSA";
				retStr[1] = "2048";
				break;
				
			case COMBO_INDEX_CERT_KEY_METHOD_RSA_4096:
				retStr[0] = "RSA";
				retStr[1] = "4096";
				break;
				
			case COMBO_INDEX_CERT_KEY_METHOD_FILE_SELECTED:
				retStr[0] = "FILE";
				retStr[1] = certKeyFile[index];
				break;
				
			default:
				retStr[0] = "FILE";
				retStr[1] = certKeyFile[index];
				break;
		}
		
		return retStr;
	}
	
	void displayCmdInTextAreaAndClear()
	{
		textAreaOpenSslCmd.setText(textAreaOpenSslCmd.getText() +  "[ " + LocalDateTime.now() + " ] --> " + cmdInterpretor.getEntireCommandLineStr() + "\n" );
		
		cmdInterpretor.clearCommandLineStr();
	}
}

