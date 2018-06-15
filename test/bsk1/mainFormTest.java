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

    @Test(expected = NoSuchFileException.class)
    public void testGetPrivate() throws Exception {
        String fileName="A:\\ABC\\b";
        mainForm.getPrivate(fileName);
    }

    
}
