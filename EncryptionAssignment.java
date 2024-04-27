import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import javax.crypto.SecretKeyFactory;
import java.util.Base64;
import java.security.SecureRandom;
import java.math.BigInteger;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Mac;
import java.util.Scanner;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileWriter;
import java.io.BufferedWriter;



public class EncryptionAssignment {

    public static void main(String[] args) {

        //variable initialization
        
        byte [] IV;
        String hmac;
        int iterations = 14000;
        byte[] ks;
        int keyLength = 0;
        String Kenc;
        String data="";
        String decrypteddata;
        String salt = "afixedsalt";
        String encrypt;

        //Getting inputs
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the password: ");
        String password = scanner.nextLine();
        System.out.print("Enter encryption algorithm (AES128, AES256, 3DES): ");
        while(true){
        String encryptvalue = scanner.nextLine();
        if ((encryptvalue.compareToIgnoreCase("aes128")== 0 )||
                    (encryptvalue.compareToIgnoreCase("aes256")== 0) || (encryptvalue.compareToIgnoreCase("3des")== 0)){
                encrypt = encryptvalue;
                break;
            }else{
                System.out.println("Please select from the options.");
            }
        }
        if((encrypt.compareToIgnoreCase("aes128")== 0 )| (encrypt.compareToIgnoreCase("aes256")== 0 )){
             IV = new byte[16];
        }
        else{
             IV = new byte[8];
        }
        System.out.print("Enter hash (SHA256, SHA512): ");
        String hash="";
        while(true){
        String hashvalue = scanner.nextLine();
        if ((hashvalue.compareToIgnoreCase("sha256")== 0 )||
                    (hashvalue.compareToIgnoreCase("sha512")== 0)){
                hash = hashvalue;
                break;
            }else{
                System.out.println("Please select from the options.");
            }
        }
        try {
           
        System.out.print("Enter the file path: ");
        String filePath = scanner.nextLine();
        File file = new File(filePath);
        if (file.exists() && file.isFile()) {
            
            StringBuilder contentBuilder = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                contentBuilder.append(line);
                contentBuilder.append(System.lineSeparator());
            }
            reader.close();
            data = contentBuilder.toString();
        } else {
            System.out.println("File not found: " + filePath);
        }
            

        //Encryption

        //Generating pbkdf key
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, (32*8));
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        if(hash.compareToIgnoreCase("sha512") == 0){
        spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, (64*8));
        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        }
        byte[] pbkdf2Key = factory.generateSecret(spec).getEncoded();

        //Generating KHMAC
        String Khmac = generateKHMAC(pbkdf2Key, salt, iterations, hash, factory);

        //Generate Kenc
        Kenc = generateKENC(pbkdf2Key, salt, iterations, hash, factory, encrypt);
        long startTime = System.nanoTime();

        //Perform Encryption
        String encryptedXml = encryptData(data, Kenc, encrypt);
        String encryptedMessage = encryptedXml.toString();
        String IVdummy = Base64.getEncoder().encodeToString(IV);

        //Generate Hmac
        hmac = generateHMAC(encrypt, encryptedMessage, IVdummy, hash, Khmac);
       
       //Appending metadata elements in metadata.xml
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();
        Element rootElement = doc.createElement("data");
        doc.appendChild(rootElement);
        Element metaDataElement = doc.createElement("metadata");
        Element algorithmElement = doc.createElement("algorithm");
        algorithmElement.appendChild(doc.createTextNode(encrypt));
        Element keyLengthElement = doc.createElement("keyLength");
        keyLengthElement.appendChild(doc.createTextNode(String.valueOf(Kenc.length() * 8)));
        Element iterationsCount = doc.createElement("iterations");
        iterationsCount.appendChild(doc.createTextNode(Integer.toString(iterations)));
        metaDataElement.appendChild(algorithmElement);
        metaDataElement.appendChild(keyLengthElement);
        metaDataElement.appendChild(iterationsCount);
        rootElement.appendChild(metaDataElement);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File("metadata.xml"));
        transformer.transform(source, result);
        
        //Appending all the details of encryption in encryptedfile.xml
        Document doctwo = dBuilder.newDocument();
        Element rootElementtwo = doctwo.createElement("data");
        doctwo.appendChild(rootElementtwo);
        Element metaDataElementtwo = doctwo.createElement("metadata");
        Element algorithmElementtwo = doctwo.createElement("algorithm");
        algorithmElementtwo.appendChild(doctwo.createTextNode(encrypt));
        Element saltValue = doctwo.createElement(("salt"));
        saltValue.appendChild(doctwo.createTextNode(salt));
        Element keyLengthElementtwo = doctwo.createElement("keyLength");
        keyLengthElementtwo.appendChild(doctwo.createTextNode(String.valueOf(Kenc.length() * 8)));
        Element iterationsCounttwo = doctwo.createElement("iterations");
        iterationsCounttwo.appendChild(doctwo.createTextNode(Integer.toString(iterations)));
        Element hmacElement = doctwo.createElement("hmac");
        hmacElement.appendChild(doctwo.createTextNode(hmac));
        String IVString = Base64.getEncoder().encodeToString(IV);
        Element IVElement = doctwo.createElement("IV");
        IVElement.appendChild(doctwo.createTextNode(IVString));
        Element KeyHmac = doctwo.createElement("Khmac");
        KeyHmac.appendChild(doctwo.createTextNode(Khmac));
        Element encryptedElement = doctwo.createElement("encryptedText");
        encryptedElement.appendChild(doctwo.createTextNode(encryptedMessage));
        metaDataElementtwo.appendChild(algorithmElementtwo);
        metaDataElementtwo.appendChild(keyLengthElementtwo);
        metaDataElementtwo.appendChild(iterationsCounttwo);
        metaDataElementtwo.appendChild(hmacElement);
        metaDataElementtwo.appendChild(IVElement);
        metaDataElementtwo.appendChild(encryptedElement);
        metaDataElementtwo.appendChild(saltValue);
        metaDataElementtwo.appendChild(KeyHmac);
        rootElementtwo.appendChild(metaDataElementtwo);
        String encrypt_iv = metaDataElementtwo.getElementsByTagName("IV").item(0).getTextContent();
        transformer = transformerFactory.newTransformer();
        source = new DOMSource(doctwo);
        StreamResult resulttwo = new StreamResult(new File("encryptedfile.xml"));
        transformer.transform(source, resulttwo);


        //Decryption
        System.out.println("Proceeding with decryption");
        System.out.print("Enter the password: ");
        String passwordTwo = scanner.nextLine();
        if(!password.equals(passwordTwo)){
            System.out.println("Wrong password");
            System.exit(1);
        }
        System.out.print("Enter the file path: ");
        String filePath2 = scanner.nextLine();
        File file2 = new File(filePath2);
        if (file2.exists() && file2.isFile()) {
            
            StringBuilder contentBuilder = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(file2));
            String line;
            while ((line = reader.readLine()) != null) {
                // Append each line to the StringBuilder
                contentBuilder.append(line);
                contentBuilder.append(System.lineSeparator());
            }
            reader.close();
        } else {
            System.out.println("File not found: " + filePath2);
        }

        //Extracting data from encrypted.xml
        dbFactory = DocumentBuilderFactory.newInstance();
        dBuilder = dbFactory.newDocumentBuilder();
        Document doc3 = dBuilder.parse(file2);
        doc3.getDocumentElement().normalize();
        rootElement = doc3.getDocumentElement();
        NodeList metaDataList3 = rootElement.getElementsByTagName("metadata");
        Element metaDataElement3 = (Element) metaDataList3.item(0);
        String decryption_algorithm = metaDataElement3.getElementsByTagName("algorithm").item(0).getTextContent();
        int decryption_keyLength = Integer.parseInt(metaDataElement3.getElementsByTagName("keyLength").item(0).getTextContent());
        int decryption_iterationsCount = Integer.parseInt(metaDataElement3.getElementsByTagName("iterations").item(0).getTextContent());
        String decryption_hmac = metaDataElement3.getElementsByTagName("hmac").item(0).getTextContent();
        String iv_value = metaDataElement3.getElementsByTagName("IV").item(0).getTextContent();
        byte[] decrypt_iv = Base64.getDecoder().decode(iv_value);
        String decrypt_encryptedText = metaDataElement3.getElementsByTagName("encryptedText").item(0).getTextContent();
        String decrypt_salt = metaDataElement3.getElementsByTagName("salt").item(0).getTextContent();
        String decrypt_Khmac = metaDataElement3.getElementsByTagName("Khmac").item(0).getTextContent();
        String decrypt_kenc =  generateKENC(pbkdf2Key, decrypt_salt, decryption_iterationsCount, hash, factory, decryption_algorithm);
        String decrypt_hmac = generateHMAC(decryption_algorithm, decrypt_encryptedText, iv_value, hash, decrypt_Khmac );
  
        //checking for tampering
        if (!decryption_hmac.equals(decrypt_hmac)) {
        System.out.println("File has been tampered. Cannot proceed!");
        System.exit(1);
}

        //Decryption
        String finalresult = decryptData(decryption_algorithm, decrypt_encryptedText, decrypt_kenc, iv_value);
        
        //Performance
        long endTime = System.nanoTime();
        long fileSize = (file).length();
        double seconds = (endTime - startTime) / 1e9;
        double throughput = fileSize / seconds;
        double iterationsPerSecond = iterations / seconds;
        File outfile = new File("result.txt");
            if (!outfile.exists()) {
                outfile.createNewFile();
                System.out.println("New file created: " + filePath);
            }
            FileWriter fileWriter = new FileWriter(outfile);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write(finalresult);
            bufferedWriter.close();
            System.out.println("Printing performance details");
            System.out.println("Encryption Throughput: " + throughput + " bytes/second");
            System.out.println("Total Iterations: " + iterations);
            System.out.println("Iterations per Second: " + iterationsPerSecond);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


   //Function that is used to decrypt
   public static String decryptData(String decryption_algorithm, String decrypt_encryptedText, String decrypt_kenc, String decrypt_iv) throws Exception {
        
    if(decryption_algorithm.compareToIgnoreCase("aes128") == 0){
        byte[] IV = Base64.getDecoder().decode(decrypt_iv);
        byte[] decodedCipher = Base64.getDecoder().decode(decrypt_encryptedText);
        SecretKeySpec keySpec = new SecretKeySpec(decrypt_kenc.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(IV));
        byte[] decryptedBytes = cipher.doFinal(decodedCipher);
        return new String(decryptedBytes);
    }

    else if (decryption_algorithm.compareToIgnoreCase("aes256") == 0 ) {
        byte[] IV = Base64.getDecoder().decode(decrypt_iv);
        byte[] decodedCipher = Base64.getDecoder().decode(decrypt_encryptedText);
        SecretKeySpec keySpec = new SecretKeySpec(decrypt_kenc.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(IV));
        byte[] decryptedBytes = cipher.doFinal(decodedCipher);
        return new String(decryptedBytes);
}
    else if (decryption_algorithm.compareToIgnoreCase("3des") == 0) {
        byte[] IV = Base64.getDecoder().decode(decrypt_iv);
        byte[] decodedCipher = Base64.getDecoder().decode(decrypt_encryptedText);
        SecretKeySpec keySpec = new SecretKeySpec(decrypt_kenc.getBytes(), "DESede");
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(IV));
        byte[] decryptedBytes = cipher.doFinal(decodedCipher);
        return new String(decryptedBytes);
    }
    return null;
    }
        

   //Function to generate HMAC 
   private static String generateHMAC(String algorithm, String encryptedMessage, String IV, String hash, String Khmac) throws Exception {
    
    String data = encryptedMessage + IV;
    byte[] keyBytes = Khmac.getBytes("UTF-8");
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, hash);
    Mac mac;
    if (hash.compareToIgnoreCase("sha256") == 0) {
        mac = Mac.getInstance("HmacSHA256");
    } else {
        mac = Mac.getInstance("HmacSHA512");
    }
    mac.init(secretKeySpec);
    byte[] hmacBytes = mac.doFinal(data.getBytes("UTF-8"));
    return bytesToHex(hmacBytes);   
}

    //Function to generate Kenc
    private static String generateKENC(byte[] pbkdf2Key, String salt, int iterations, String hash, SecretKeyFactory factory, String encrypt) throws Exception{
    
    byte[] ks;
    int keyLength = 0;
    
    if(encrypt.compareToIgnoreCase("aes256") == 0) {
        KeySpec encspec = new PBEKeySpec(toHex(pbkdf2Key).toCharArray(), salt.getBytes(), iterations, (32*4));
        ks = factory.generateSecret(encspec).getEncoded();
    }else if(encrypt.compareToIgnoreCase("aes128") == 0){
        KeySpec encspec = new PBEKeySpec(toHex(pbkdf2Key).toCharArray(), salt.getBytes(), iterations, (16 * 4));
        ks = factory.generateSecret(encspec).getEncoded();
    }
    else{
        KeySpec encspec = new PBEKeySpec(toHex(pbkdf2Key).toCharArray(), salt.getBytes(), iterations, (24*4));
        ks = factory.generateSecret(encspec).getEncoded();
    } 
    return toHex(ks);  
    }

    //Function to encrypt Data
    private static String encryptData(String mess, String Kenc,  String encrypt) throws Exception {
    if(encrypt.compareToIgnoreCase("aes128") == 0){
        byte[] output;
        byte[] IV = new byte[16];
        SecretKeySpec keySpec = new SecretKeySpec(Kenc.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(IV));
        output = cipher.doFinal(mess.getBytes());
        String encryptedMessage = Base64.getEncoder().encodeToString(output);
        return encryptedMessage;
    }
    else if (encrypt.compareToIgnoreCase("3des") == 0) {
        byte[] output;
        byte[] IV = new byte[8]; // IV size for 3DES is 8 bytes
        SecretKeySpec keySpec = new SecretKeySpec(Kenc.getBytes(), "DESede");
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(IV));
        output = cipher.doFinal(mess.getBytes());
        String encryptedMessage = Base64.getEncoder().encodeToString(output);
        return encryptedMessage;
    }

    else if (encrypt.compareToIgnoreCase("aes256") == 0) {
        byte[] output;
        byte[] IV = new byte[16]; // IV size for AES is 16 bytes
        SecretKeySpec keySpec = new SecretKeySpec(Kenc.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(IV));
        output = cipher.doFinal(mess.getBytes());
        String encryptedMessage = Base64.getEncoder().encodeToString(output);
        return encryptedMessage;
}
    return null;
   
    }


    //Function to generateKHMAC
    private static String generateKHMAC(byte[] pbkdf2Key, String salt, int iterations, String hash, SecretKeyFactory factory) throws Exception{
        KeySpec hmacspec = new PBEKeySpec(toHex(pbkdf2Key).toCharArray(), salt.getBytes(), iterations, (32*8));
        if (hash.compareToIgnoreCase("sha512") == 0) {
            hmacspec = new PBEKeySpec(toHex(pbkdf2Key).toCharArray(), salt.getBytes(), iterations, (64*8));
        }
        return toHex(factory.generateSecret(hmacspec).getEncoded());
    }


    private static String toHex(byte[] bytearray){
        BigInteger big = new BigInteger(1, bytearray);
        String hexoutput = big.toString(16);
        int paddingLength = (bytearray.length * 2) - hexoutput.length();
        if(paddingLength > 0)
            return String.format("%0" + paddingLength + "d", 0) + hexoutput;
        else
            return hexoutput;
    }

   public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
}
