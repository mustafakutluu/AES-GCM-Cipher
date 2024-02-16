import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import com.aes.cipher.AESKeyGenerator;
import com.aes.cipher.AESUtil;


public class EncryptTest {

	static public void main(String[] arg1s) throws Exception {

		textEncryptAndDecryptTest();

	}

	/*** Security text encryp test
	 * 
	 * @throws InvalidKeySpecException
	 * @throws IOException */
	public static void textEncryptAndDecryptTest() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException, IOException {

		String plainText = "mk_test";
		String password = "mk_password";
		String keyPath = "AES/cipher_test.key";

		SecretKey key = AESKeyGenerator.generateKey(password);
		String cipherText = AESUtil.encrypt(plainText, key);
		String decryptedCipherText = AESUtil.decrypt(cipherText, key);

		System.out.println("plainText: " + plainText);
		System.out.println("cipherText: " + cipherText);
		System.out.println("decryptedCipherText: " + decryptedCipherText);

		System.out.println("\n");

		SecretKey keyFromFile = AESKeyGenerator.generateKeyFromFile(keyPath);
		String cipherTextFile = AESUtil.encrypt(plainText, keyFromFile);
		String decryptedCipherTextFile = AESUtil.decrypt(cipherTextFile, keyFromFile);

		System.out.println("plainText: " + plainText);
		System.out.println("cipherText: " + cipherTextFile);
		System.out.println("decryptedCipherText: " + decryptedCipherTextFile);
	}

}
