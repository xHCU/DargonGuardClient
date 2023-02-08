package org.dragonguard;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.MessageDigest;

import javax.swing.JOptionPane;

import org.dragonguard.utils.Encryption;
import org.dragonguard.utils.Encryption2;
import org.dragonguard.utils.Encryption3;
import org.json.JSONObject;

public class Main {

	private static byte[] aeskey = {65, 67, 77, 70, 65, 66, 115, 99, 65, 68, 81, 81, 65, 67, 52, 117, 65, 68, 77, 77, 65, 65, 99, 98, 65, 66, 119, 100, 65, 67, 52, 83, 65, 66, 73, 79, 65, 66, 52, 97, 65, 68, 115, 110, 65, 65, 85, 105};
	private static byte[] aeskey2 = {65, 67, 115, 43, 65, 67, 73, 78, 65, 68, 85, 43, 65, 68, 48, 66, 65, 68, 52, 84, 65, 68, 119, 90, 65, 67, 89, 103, 65, 65, 103, 54, 65, 68, 85, 114, 65, 65, 107, 102, 65, 65, 69, 49, 65, 65, 111, 118, 65, 67, 119, 98};
	private static byte[] aeskey3 = {65, 67, 119, 110, 65, 66, 56, 104, 65, 67, 52, 67, 65, 68, 73, 110, 65, 68, 81, 69, 65, 65, 119, 84, 65, 68, 81, 50, 65, 68, 99, 104, 65, 65, 65, 112, 65, 66, 73, 69, 65, 66, 85, 80, 65, 68, 111, 118, 65, 68, 48, 50};
	private static byte[] aeskey4 = {65, 66, 81, 107, 65, 67, 107, 53, 65, 65, 89, 83, 65, 66, 119, 114, 65, 65, 73, 67, 65, 67, 48, 103, 65, 67, 99, 113, 65, 66, 119, 82, 65, 65, 99, 54, 65, 68, 65, 114, 65, 68, 56, 74, 65, 67, 119, 84, 65, 65, 119, 49, 65, 67, 115, 87};
	
	public static void main(String[] args) throws IOException, InterruptedException {
		Socket socket = new Socket("localhost",1337);  
		DataInputStream din=new DataInputStream(socket.getInputStream());  
		PrintWriter output = new PrintWriter(socket.getOutputStream(),true);
		Encryption aes = new Encryption();
		try {
			//////////////Write your code here/////////////
			String toEncrypt =  System.getenv("COMPUTERNAME") + System.getProperty("user.name") + System.getenv("PROCESSOR_IDENTIFIER") + System.getenv("PROCESSOR_LEVEL");
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(toEncrypt.getBytes());
            StringBuffer hexString = new StringBuffer();
            
            byte byteData[] = md.digest();
            
            for (byte aByteData : byteData) {
                String hex = Integer.toHexString(0xff & aByteData);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            ///////////////////////////////////////////////
            Encryption2 encryption = new Encryption2();
            Encryption3 encryption2 = new Encryption3();
            KeyAES1 key = new KeyAES1();
			String firstKey = encryption.decryptXORBase64(new String(key.key));
			JSONObject json = new JSONObject();
			json.put("stage", 1);
			json.put("message", aes.encrypt("getIp", firstKey));
			output.println(json.toString());
			String string = din.readUTF();
			JSONObject json2 = new JSONObject(string);
			KeyAES2 key2 = new KeyAES2();
			String secondKey = encryption2.decryptXORBase64(new String(key2.key)) + aes.decrypt(json2.getString("key"), firstKey) + aes.decrypt(json2.getString("secret"), firstKey);
			json.clear();
			json.put("stage", 2);
			json.put("message", aes.encrypt(hexString.toString(), secondKey));
			output.println(json.toString());
			string = din.readUTF();
			JSONObject json3 = new JSONObject(string);
			if (json3.has("error") && json3.getString("error").equals("1")) {
				JOptionPane.showMessageDialog(null, "Error: 402 Your HWID not found in the database!");
				System.exit(0);
			}
			if (json3.has("error") && json3.getString("error").equals("3")) {
				JOptionPane.showMessageDialog(null, "Error: 400 Bad request!");
				System.exit(0);
			}
			KeyAES3 key3 = new KeyAES3();
			String thirddKey = encryption.decryptXORBase64(new String(key3.key)) + encryption2.decryptXORBase64(new String(aeskey)) + hexString.toString() + aes.decrypt(json3.getString("secret"), secondKey);
			json.clear();
			json.put("stage", 3);
			json.put("message", aes.encrypt(hexString.toString(), secondKey + encryption.decryptXORBase64(new String(aeskey2))));
			json.put("key", aes.encrypt(aes.decrypt(json3.getString("secret"), secondKey), secondKey + encryption2.decryptXORBase64(new String(aeskey3))));
			output.println(json.toString());
			string = din.readUTF();
			JSONObject json6 = new JSONObject(string);
			if (json6.has("error") && json6.getString("error").equals("2")) {
				JOptionPane.showMessageDialog(null, "Error: 408 Request Timeout");
				System.exit(0);
			}
			if (json3.has("error") && json3.getString("error").equals("3")) {
				JOptionPane.showMessageDialog(null, "Error: 400 Bad request!");
				System.exit(0);
			}
			if (!aes.decrypt(json6.getString("key"), thirddKey).equals(encryption.decryptXORBase64(new String(aeskey4)))) {
				JOptionPane.showMessageDialog(null, "Error: 401 Invalid jar!");
				System.exit(0);
			}
		} catch(Exception e) {
			socket.close();
			System.exit(0);
		}
		System.out.println("YEY!");
		socket.close();
	}
}
