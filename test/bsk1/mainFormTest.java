/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1;

import org.junit.Test;
import java.io.File;
import java.nio.file.NoSuchFileException;

/**
 *
 * @author Kyrychok-PC
 */
public class mainFormTest {
    
    public mainFormTest() {
    }

    /**
     * Test of getFileExtension method, of class mainForm.
     */
    @Test
    public void testGetFileExtension() {
        String fileName="myFile.txt";
        mainForm m=new mainForm();
        String extension=m.getFileExtension(new File(fileName));
        assert(extension.equals("txt"));
    }
    
    @Test
    public void testGetFileExtensionWithEmptyFileName() {
        mainForm m=new mainForm();
        File testFile=null;
        String extension=m.getFileExtension(testFile);
        assert(extension.equals(""));
    }

    @Test
    public void testPasswordIsOk()
    {
        mainForm m=new mainForm();
        assert(m.passwordIsOk("Passw0r|)"));
        assert(!m.passwordIsOk("Password"));
    }
    /**
     * Test of getPrivate method, of class mainForm.
     */
    @Test(expected = NoSuchFileException.class)
    public void testGetPrivate() throws Exception {
        String fileName="A:\\ABC\\b";
        mainForm.getPrivate(fileName);
        
    }

    /**
     * Test of getPublic method, of class mainForm.
     */
    @Test
    public void testGetPublic() throws Exception {
    }

    /**
     * Test of RSAencrypt method, of class mainForm.
     */
    @Test
    public void testRSAencrypt() throws Exception {
    }

    /**
     * Test of RSAdecrypt method, of class mainForm.
     */
    @Test
    public void testRSAdecrypt() throws Exception {
    }

    /**
     * Test of writeXML method, of class mainForm.
     */
    @Test
    public void testWriteXML_8args() {
    }

    /**
     * Test of writeXML method, of class mainForm.
     */
    @Test
    public void testWriteXML_3args() {
    }

    /**
     * Test of generateKey method, of class mainForm.
     */
    @Test
    public void testGenerateKey() throws Exception {
    }

    /**
     * Test of ecbEncrypt method, of class mainForm.
     */
    @Test
    public void testEcbEncrypt() throws Exception {
    }

    /**
     * Test of ecbDecrypt method, of class mainForm.
     */
    @Test
    public void testEcbDecrypt() throws Exception {
    }

    /**
     * Test of cbcEncrypt method, of class mainForm.
     */
    @Test
    public void testCbcEncrypt() throws Exception {
    }

    /**
     * Test of cbcDecrypt method, of class mainForm.
     */
    @Test
    public void testCbcDecrypt() throws Exception {
    }

    /**
     * Test of cfbEncrypt method, of class mainForm.
     */
    @Test
    public void testCfbEncrypt() throws Exception {
    }

    /**
     * Test of ofbEncrypt method, of class mainForm.
     */
    @Test
    public void testOfbEncrypt() throws Exception {
    }

    /**
     * Test of cfbDecrypt method, of class mainForm.
     */
    @Test
    public void testCfbDecrypt() throws Exception {
    }

    /**
     * Test of ofbDecrypt method, of class mainForm.
     */
    @Test
    public void testOfbDecrypt() throws Exception {
    }

    /**
     * Test of getString method, of class mainForm.
     */
    @Test
    public void testGetString_String_Element() {
    }

    /**
     * Test of getStringbyNodeValue method, of class mainForm.
     */
    @Test
    public void testGetStringbyNodeValue() {
    }

    /**
     * Test of getString method, of class mainForm.
     */
    @Test
    public void testGetString_3args() {
    }

    /**
     * Test of generateKeysForUser method, of class mainForm.
     */
    @Test
    public void testGenerateKeysForUser() {
    }

    /**
     * Test of main method, of class mainForm.
     */
    @Test
    public void testMain() {
    }
    
}
