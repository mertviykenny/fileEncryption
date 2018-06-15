/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1;

import java.io.File;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileSystemView;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author Kyrychok
 */
public class mainForm extends javax.swing.JFrame {

    /**
     * Creates new form mainForm
     */
    public mainForm() {
        initComponents();
    }

    public String getFileExtension(File file) {
        if (file == null) {
            return "";
        }
        String name = file.getName();
        int i = name.lastIndexOf('.');
        String ext = i > 0 ? name.substring(i + 1) : "";
        return ext;
    }

    public static PrivateKey getPrivate(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

    }

    public static byte[] RSAencrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message.getBytes());
    }

    public static byte[] RSAdecrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encrypted);
    }

    public void writeXML(String filename, String alghoritmName, int keySize, int blockSize, String cipherMode, String AESKeyBase64, String extension, byte[] IV) {

        try {

            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            Element rootElement = doc.createElement("EncryptedFileHeader");
            doc.appendChild(rootElement);

            Element alg = doc.createElement("Alghoritm");
            alg.appendChild(doc.createTextNode(alghoritmName));
            rootElement.appendChild(alg);

            Element s = doc.createElement("Size");
            s.appendChild(doc.createTextNode(Integer.toString(keySize)));
            rootElement.appendChild(s);

            Element b = doc.createElement("BlockSize");
            b.appendChild(doc.createTextNode(Integer.toString(blockSize)));
            rootElement.appendChild(b);

            Element c = doc.createElement("CipherMode");
            c.appendChild(doc.createTextNode(cipherMode));
            rootElement.appendChild(c);
            
            Element e = doc.createElement("Extension");
            e.appendChild(doc.createTextNode(extension));
            rootElement.appendChild(e);

            Element vector = doc.createElement("IV");
            if (IV != null) {
                vector.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(IV)));
            } else {
                vector.appendChild(doc.createTextNode("null"));
            }
            rootElement.appendChild(vector);

            Element approved_users = doc.createElement("ApprovedUsers");

            for (int iter = 0; iter < userComboBox.getItemCount(); iter++) {
                Element user = doc.createElement("User");

                Element u = doc.createElement("Name");
                u.appendChild(doc.createTextNode(userComboBox.getItemAt(iter)));
                user.appendChild(u);
                Element AESKeyEncryptedWithRsa = doc.createElement("AESKeyEncryptedWithRsa");

                PublicKey publicKey = getPublic(inputFile.getParent() + "\\openkeys\\" + userComboBox.getItemAt(iter) + ".open");
                byte[] encrypted = RSAencrypt(publicKey, AESKeyBase64);

                AESKeyEncryptedWithRsa.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(encrypted)));
                user.appendChild(AESKeyEncryptedWithRsa);
                approved_users.appendChild(user);
            }
            rootElement.appendChild(approved_users);

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(filename));
            transformer.transform(source, result);
        } catch (Exception e) {
            System.out.println(e.getMessage());

        }

    }

    public static void writeXML(String filename, BigInteger modulus, BigInteger exp) {

        try {

            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            Element rootElement = doc.createElement("OpenKey");
            doc.appendChild(rootElement);
            Element alg = doc.createElement("Modulus");
            alg.appendChild(doc.createTextNode(String.valueOf(modulus)));
            rootElement.appendChild(alg);

            Element s = doc.createElement("Exponent");
            s.appendChild(doc.createTextNode(String.valueOf(exp)));
            rootElement.appendChild(s);

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(filename));
            transformer.transform(source, result);

        } catch (Exception e) {
            System.out.println(e.getMessage());

        }

    }

    public static SecretKey generateKey(int bits)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(bits);
        return keyGenerator.generateKey();
    }

    public static byte[] ecbEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] ecbDecrypt(SecretKey key, byte[] cipherText)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    byte[] IV_generated;

    public byte[] cbcEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        IV_generated = cipher.getIV();
        return cipher.doFinal(data);
    }

    public byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    public byte[] cfbEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        IV_generated = cipher.getIV();
        return cipher.doFinal(data);
    }

    public byte[] ofbEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        IV_generated = cipher.getIV();
        return cipher.doFinal(data);
    }

    public byte[] cfbDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    public byte[] ofbDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        EncryptButton = new javax.swing.JButton();
        DecryptButton = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        outputNameText = new javax.swing.JTextField();
        keySizeComboBox = new javax.swing.JComboBox<>();
        modeComboBox = new javax.swing.JComboBox<>();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        userComboBox = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        userNameTextBox = new javax.swing.JTextField();
        adduser = new javax.swing.JButton();
        RemoveButton = new javax.swing.JButton();
        PasswordTextField = new javax.swing.JTextField();
        Password = new javax.swing.JLabel();
        DecryptPrivateKey = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setResizable(false);

        EncryptButton.setText("Encrypt");
        EncryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                EncryptButtonActionPerformed(evt);
            }
        });

        DecryptButton.setText("Decrypt");
        DecryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DecryptButtonActionPerformed(evt);
            }
        });

        jButton3.setText("SelectFile");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jLabel2.setText("noFileSelected");

        jLabel3.setText("outputName");

        outputNameText.setText("myname.encrypted");

        keySizeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "128", "192", "256" }));

        modeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "ECB", "CBC", "CFB", "OFB" }));

        jLabel4.setText("keySize");

        jLabel5.setText("mode");

        jLabel1.setText("Users");

        jLabel7.setText("User Name");

        userNameTextBox.setText("userName");

        adduser.setText("Add");
        adduser.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                adduserActionPerformed(evt);
            }
        });

        RemoveButton.setText("RemoveUser");
        RemoveButton.setToolTipText("");
        RemoveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RemoveButtonActionPerformed(evt);
            }
        });

        PasswordTextField.setText("Passw0r|)");

        Password.setText("Password");

        DecryptPrivateKey.setText("DecryptPrivateKey");
        DecryptPrivateKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DecryptPrivateKeyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(outputNameText, javax.swing.GroupLayout.DEFAULT_SIZE, 569, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 543, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jButton3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(EncryptButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jLabel4)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(keySizeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(jLabel5)
                                .addGap(18, 18, 18)
                                .addComponent(modeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(136, 136, 136)
                                .addComponent(DecryptButton))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(userComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(29, 29, 29)
                                .addComponent(RemoveButton))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel7)
                                    .addComponent(Password))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(PasswordTextField)
                                    .addComponent(userNameTextBox, javax.swing.GroupLayout.DEFAULT_SIZE, 101, Short.MAX_VALUE))
                                .addGap(18, 18, 18)
                                .addComponent(adduser, javax.swing.GroupLayout.PREFERRED_SIZE, 64, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(DecryptPrivateKey)))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(EncryptButton)
                    .addComponent(DecryptButton)
                    .addComponent(jButton3)
                    .addComponent(keySizeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(modeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4)
                    .addComponent(jLabel5))
                .addGap(18, 18, 18)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(outputNameText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(userComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(RemoveButton))
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(userNameTextBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel7))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(PasswordTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(Password)))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(29, 29, 29)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(adduser, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(DecryptPrivateKey))))
                .addContainerGap(22, Short.MAX_VALUE))
        );

        setBounds(0, 0, 680, 277);
    }// </editor-fold>//GEN-END:initComponents
File inputFile;
    boolean fileSelected = false;
    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        int returnValue = jfc.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            inputFile = jfc.getSelectedFile();
            System.out.println(inputFile.getAbsolutePath() + " ext=" + getFileExtension(inputFile));
            jLabel2.setText(inputFile.getAbsolutePath());
            outputNameText.setText(inputFile.getName() + ".ENC");
            fileSelected = true;
        }
    }//GEN-LAST:event_jButton3ActionPerformed

    private void EncryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_EncryptButtonActionPerformed

        if (fileSelected) {
            if (userComboBox.getModel().getSize() > 0) {

                try {
                    String output_name_and_extension = null;
                    if (!outputNameText.getText().toString().isEmpty()) {
                        output_name_and_extension = inputFile.getParent().toString() + "\\" + outputNameText.getText().toString();
                    } else {
                        output_name_and_extension = inputFile.getAbsolutePath() + ".ENC";
                    }
                    String manifest_name = output_name_and_extension + ".manifest";
                    System.out.println("encrypting file" + inputFile.getAbsolutePath() + " and writing to" + output_name_and_extension);
                    InputStream input_stream = new FileInputStream(inputFile);
                    SecretKey key = generateKey(Integer.parseInt(keySizeComboBox.getSelectedItem().toString()));
                    byte[] data = Files.readAllBytes(Paths.get(inputFile.getAbsolutePath()));
                    byte[] encrypted_data = null;

                    IV_generated = null;
                    if (modeComboBox.getSelectedItem().toString().equals("ECB")) {
                        encrypted_data = ecbEncrypt(key, data);
                        Files.write(new File(output_name_and_extension).toPath(), encrypted_data);
                        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                        writeXML(manifest_name, "AES", Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), 128, "ECB", encodedKey, getFileExtension(inputFile), IV_generated);
                    }
                    if ("CBC".equals(modeComboBox.getSelectedItem().toString())) {
                        encrypted_data = cbcEncrypt(key, data);
                        Files.write(new File(output_name_and_extension).toPath(), encrypted_data);
                        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                        writeXML(manifest_name, "AES", Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), 128, "CBC", encodedKey, getFileExtension(inputFile), IV_generated);
                    }
                    if ("CFB".equals(modeComboBox.getSelectedItem().toString())) {
                        encrypted_data = cfbEncrypt(key, data);
                        Files.write(new File(output_name_and_extension).toPath(), encrypted_data);
                        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                        writeXML(manifest_name, "AES", Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), 128, "CFB", encodedKey, getFileExtension(inputFile), IV_generated);
                    }
                    if ("OFB".equals(modeComboBox.getSelectedItem().toString())) {
                        encrypted_data = ofbEncrypt(key, data);
                        Files.write(new File(output_name_and_extension).toPath(), encrypted_data);
                        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                        writeXML(manifest_name, "AES", Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), 128, "OFB", encodedKey, getFileExtension(inputFile), IV_generated);
                    }
                    System.out.println("Finished Encrypting");

                    File privateKeyFolder = new File(inputFile.getParent() + "\\closedkeys");
                    String[] entries = privateKeyFolder.list();
                    for (String s : entries) {
                        File currentFile = new File(privateKeyFolder.getPath(), s);
                        currentFile.delete();
                    }
                    privateKeyFolder.delete();
                } catch (Exception e) {
                    System.out.println(e.getMessage() + " " + e.getStackTrace());
                }
            } else {
                JOptionPane optionPane = new JOptionPane("0 users", JOptionPane.WARNING_MESSAGE);
                JDialog dialog = optionPane.createDialog("Warning!");
                dialog.setAlwaysOnTop(true); // to show top of all other application
                dialog.setVisible(true); // to visible the dialog 

            }

        } else {
            showFileNotSelectedWarning();
        }
    }//GEN-LAST:event_EncryptButtonActionPerformed
    protected String getString(String tagName, Element element) {
        NodeList list = element.getElementsByTagName(tagName);
        if (list != null && list.getLength() > 0) {
            NodeList subList = list.item(0).getChildNodes();

            if (subList != null && subList.getLength() > 0) {
                return subList.item(0).getNodeValue();
            }
        }

        return null;
    }

    protected String getStringbyNodeValue(String tagName, Element element) {
        NodeList list = element.getElementsByTagName("ApprovedUsers");
        for (int i = 0; i < list.getLength(); i++) {
            if (list.item(i).getNodeType() == Node.ELEMENT_NODE) {
                NodeList list1 = list.item(i).getChildNodes();
                for (int j = 0; j < list1.getLength(); j++) {
                    NodeList list2 = list1.item(j).getChildNodes();
                    if (list2.item(0).getTextContent().compareTo(tagName) == 0) {
                        return list2.item(0).getNextSibling().getTextContent();
                    }
                }
            }
        }
        return null;
    }

    protected String getString(String tagName, Element element, int i) {
        NodeList list = element.getElementsByTagName(tagName);
        if (list != null && list.getLength() > 0) {
            NodeList subList = list.item(i).getChildNodes();

            if (subList != null && subList.getLength() > 0) {
                return subList.item(0).getNodeValue();
            }
        }

        return null;
    }

    private int getSelectedUser() {

        return userComboBox.getSelectedIndex();
    }
    private void DecryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DecryptButtonActionPerformed
        if (fileSelected) {
            try {
                File manifestFile = new File(inputFile.getAbsolutePath() + ".manifest");
                
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document document = builder.parse(manifestFile);
                Element rootElement = document.getDocumentElement();
                String alghoritm = getString("Alghoritm", rootElement);
                String size_s = getString("Size", rootElement);
                String blockSize_s = getString("BlockSize", rootElement);
                String cipherMode = getString("CipherMode", rootElement);
                String IV = getString("IV", rootElement);
                String Extension = getString("Extension",rootElement);
                
                String output_name_and_extension = inputFile.getParent()+"\\"+outputNameText.getText()+"."+Extension;
                System.out.println(output_name_and_extension);
                
                
                String currentUser=userNameTextBox.getText();

                PrivateKey privateKey = getPrivate(inputFile.getParent() + "\\closedkeys\\" + currentUser + ".closed");
                
                String encrypted_AES_key_base64 = getStringbyNodeValue(currentUser, rootElement);
                
                byte[] AESKey = RSAdecrypt(privateKey, Base64.getDecoder().decode(encrypted_AES_key_base64));   // getString("AESKeyBase64", rootElement);

                int size = Integer.parseInt(size_s);
                int blockSize = Integer.parseInt(blockSize_s);
                byte[] encrypted_data = Files.readAllBytes(Paths.get(inputFile.getAbsolutePath()));
                byte[] decodedKey = Base64.getDecoder().decode(AESKey);
                SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
                System.out.println("cipher=" + cipherMode);
                if (cipherMode.compareTo("ECB") == 0) {
                    byte[] decrypted_data = ecbDecrypt(originalKey, encrypted_data);
                    Files.write(new File(output_name_and_extension).toPath(), decrypted_data);
                }
                if (cipherMode.compareTo("CBC") == 0) {
                    byte[] decrypted_data = cbcDecrypt(originalKey, Base64.getDecoder().decode(IV), encrypted_data);
                    Files.write(new File(output_name_and_extension).toPath(), decrypted_data);
                }
                if (cipherMode.compareTo("CFB") == 0) {
                    byte[] decrypted_data = cfbDecrypt(originalKey, Base64.getDecoder().decode(IV), encrypted_data);
                    Files.write(new File(output_name_and_extension).toPath(), decrypted_data);
                }
                if (cipherMode.compareTo("OFB") == 0) {
                    byte[] decrypted_data = ofbDecrypt(originalKey, Base64.getDecoder().decode(IV), encrypted_data);
                    Files.write(new File(output_name_and_extension).toPath(), decrypted_data);
                }
                
                System.out.println("finished writing");

            } catch (Exception e) {
                System.out.println(e.getMessage()+" at\n"+e.getStackTrace());
            }
        } else {
            showFileNotSelectedWarning();
        }
    }//GEN-LAST:event_DecryptButtonActionPerformed
    private void showFileNotSelectedWarning() {
        System.out.println("Select file");
        JOptionPane optionPane = new JOptionPane("Select file!", JOptionPane.WARNING_MESSAGE);
        JDialog dialog = optionPane.createDialog("Warning!");
        dialog.setAlwaysOnTop(true); // to show top of all other application
        dialog.setVisible(true); // to visible the dialog 
    }

    public boolean passwordIsOk(String pass) {
        if (pass.length() >= 8) {
            if (pass.matches("(.*[A-Z].*)")) {
                if (pass.matches("(.*[0-9].*)")) {
                    if (pass.matches("(.*[ ! # @ $ % ^ & * ( ) - _ = + [ ] ; : ' \" , < . > / ?].*)")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void generateKeysForUser(String userName) {
        if (fileSelected) {
            SecureRandom rand = new SecureRandom();
            File open_keys_folder = new File(inputFile.getParent() + "\\openkeys");
            open_keys_folder.mkdir();
            File closed_keys_folder = new File(inputFile.getParent() + "\\closedkeys");
            closed_keys_folder.mkdir();

            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048, rand);
                KeyPair kp = keyGen.generateKeyPair();
                Key privateKey = kp.getPrivate();
                Key publicKey = kp.getPublic();

                byte[] prkey = privateKey.getEncoded();
                FileOutputStream prfos = new FileOutputStream(closed_keys_folder + "\\" + userName + ".closed");
                prfos.write(prkey);
                prfos.close();

                byte[] pukey = publicKey.getEncoded();
                FileOutputStream pufos = new FileOutputStream(open_keys_folder + "\\" + userName + ".open");
                pufos.write(pukey);
                pufos.close();

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private void EncryptPrivateKeyWithAes(String user) {
        File encrypted_keys_folder = new File(inputFile.getParentFile() + "\\encryptedPrivate");
        File keyToEncrypt = new File(inputFile.getParent() + "\\closedkeys\\" + user + ".closed");
        encrypted_keys_folder.mkdir();
        try {

            MessageDigest crypt = MessageDigest.getInstance("SHA-256");
            crypt.reset();
            crypt.update(PasswordTextField.getText().getBytes("UTF-8"));
            byte[] sha256 = crypt.digest();

            byte[] private_key = Files.readAllBytes(Paths.get(keyToEncrypt.getAbsolutePath()));

            SecretKey myKey = new SecretKeySpec(
                    sha256,
                    0,
                    sha256.length,
                    "AES/ECB/PKCS7Padding");
            byte[] encryptedKey = ecbEncrypt(myKey, private_key);

            Files.write(new File(encrypted_keys_folder + "\\" + user + ".encrypted").toPath(), Base64.getEncoder().encode(encryptedKey));

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }
    private void adduserActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_adduserActionPerformed
        if (fileSelected) {
            if (passwordIsOk(PasswordTextField.getText())) {
                generateKeysForUser(userNameTextBox.getText());
                EncryptPrivateKeyWithAes(userNameTextBox.getText());
                userComboBox.addItem(userNameTextBox.getText());
            } else {
                JOptionPane optionPane = new JOptionPane("Password must have 1 letter,number,special symbol", JOptionPane.WARNING_MESSAGE);
                JDialog dialog = optionPane.createDialog("Warning!");
                dialog.setAlwaysOnTop(true); // to show top of all other application
                dialog.setVisible(true); // to visible the dialog 

            }
        } else {
            showFileNotSelectedWarning();
        }
    }//GEN-LAST:event_adduserActionPerformed

    private void RemoveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RemoveButtonActionPerformed
        userComboBox.removeItem(userComboBox.getSelectedItem());
        // TODO add your handling code here:
    }//GEN-LAST:event_RemoveButtonActionPerformed

    private void DecryptPrivateKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DecryptPrivateKeyActionPerformed
        if (fileSelected) {
            try {
                String user = userNameTextBox.getText();
                File encrypted_keys_folder = new File(inputFile.getParentFile() + "\\encryptedPrivate");
                File closedKeyFolder = new File(inputFile.getParentFile() + "\\closedkeys");
                closedKeyFolder.mkdir();
                MessageDigest crypt = MessageDigest.getInstance("SHA-256");
                crypt.reset();
                crypt.update(PasswordTextField.getText().getBytes("UTF-8"));
                byte[] sha256 = crypt.digest();
                byte[] encrypted_key = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(new File(encrypted_keys_folder + "\\" + user + ".encrypted").getAbsolutePath())));

                SecretKey myKey = new SecretKeySpec(sha256, 0, sha256.length, "AES/ECB/PKCS7Padding");
                byte[] decryptedKey = ecbDecrypt(myKey, encrypted_key);
                Files.write(new File(closedKeyFolder + "\\" + user + ".closed").toPath(), decryptedKey);

            } catch (IOException | GeneralSecurityException e) {
                System.out.println("exc" + e.getMessage()); //Brak interakcji aplikacji podczas próby deszyfracji przez nieuprawnionego użytkownika 0
            }
        } else {
            showFileNotSelectedWarning();
        }
    }//GEN-LAST:event_DecryptPrivateKeyActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(mainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(mainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(mainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(mainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new mainForm().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton DecryptButton;
    private javax.swing.JButton DecryptPrivateKey;
    private javax.swing.JButton EncryptButton;
    private javax.swing.JLabel Password;
    private javax.swing.JTextField PasswordTextField;
    private javax.swing.JButton RemoveButton;
    private javax.swing.JButton adduser;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JComboBox<String> keySizeComboBox;
    private javax.swing.JComboBox<String> modeComboBox;
    private javax.swing.JTextField outputNameText;
    private javax.swing.JComboBox<String> userComboBox;
    private javax.swing.JTextField userNameTextBox;
    // End of variables declaration//GEN-END:variables
}
