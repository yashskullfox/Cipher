import java.io.*;
import java.lang.*;
import java.security.*;
import java.security.interfaces.*;
import java.math.*;
import cryptix.util.core.BI;
import cryptix.util.core.Hex;
import cryptix.provider.key.*;
import cryptix.provider.md.*;
 
class testDSA {
 
	public static void main(String[] args) {
 
    	try {
        	        	FileOutputStream outFile = new FileOutputStream("DSA.out");
        	        	PrintStream output = new PrintStream(outFile);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        	        	SecureRandom ran = new SecureRandom();
        	        	byte[] bb = new byte[20];
        	        	ran.nextBytes(bb);
        	        	String w = cryptix.util.core.Hex.dumpString(bb);
        	        	output.println("20 random bytes: " + w);
        	        	keyGen.initialize(1024, ran);
        	KeyPair pair = keyGen.generateKeyPair();
        	Signature dsa = Signature.getInstance("SHA/DSA");
        	        	BigInteger x, y, g, p, q, z, zz, phash, sig1;
        	        	DSAKey priv2 = (DSAKey) pair.getPrivate();
        	        	DSAParams params = priv2.getParams();
        	        	g = (BigInteger) params.getG();
        	        	w = cryptix.util.core.BI.dumpString(g);
        	        	output.println("generator g = " + w);
        	        	p = (BigInteger) params.getP();
        	        	w = cryptix.util.core.BI.dumpString(p);
        	        	output.println("prime p = " + w);
        	        	q = (BigInteger) params.getQ();
        	        	w = cryptix.util.core.BI.dumpString(q);
        	        	output.println("order q of group G(q) = " + w);
        	        	z = p.mod(q);
        	        	w = cryptix.util.core.BI.dumpString(z);
        	        	output.println("p mod q = " + w);
        	        	z = g.modPow(q,p);
        	        	w = cryptix.util.core.BI.dumpString(z);
        	        	output.println("g^q mod p = " + w);
            DSAPrivateKey priv = (DSAPrivateKey) pair.getPrivate();
        	        	x = (BigInteger) priv.getX();
        	        	String sx = cryptix.util.core.BI.dumpString(x);
        	        	output.println(" ");
        	        	output.println("private key x = " + sx);
            DSAPublicKey pub = (DSAPublicKey) pair.getPublic();
        	        	y = (BigInteger) pub.getY();
        	        	String sy = cryptix.util.core.BI.dumpString(y);
        	        	output.println(" ");
        	        	output.println("public key y = " + sy);
        	        	z = g.modPow(x,p);
        	        	w = cryptix.util.core.BI.dumpString(z);
        	        	output.println(" ");
        	        	output.println("Note here that the value of ");
        	        	output.println("g^x mod p = " + w);
        	        	output.println("which verifies the public key y.");   	        	
        	        	output.println(" ");
        	        	MessageDigest sha = MessageDigest.getInstance("SHA-1");
        	        	byte[] yval = y.toByteArray();         	
        	        	byte[] ident = sha.digest(yval);
        	        	String sident = cryptix.util.core.Hex.dumpString(ident);
        	        	output.println("SHA-1 hash of y = " + sident);
     	   dsa.initSign(priv);
        	        	MessageDigest md = MessageDigest.getInstance("SHA-1");
    		FileInputStream fis = new FileInputStream(args[0]);
        	        	byte b;
    		while (fis.available() != 0) {
    		        	b = (byte) fis.read();
    		        	md.update(b);
    		        	dsa.update(b);
           	     	        	};
    		fis.close();
        	        	byte[] hash = md.digest();
        	        	w = cryptix.util.core.Hex.dumpString(hash);
        	        	output.println("the SHA-1 hash of " + args[0] + " is " + w);
        	        	w = cryptix.util.core.Hex.dumpString(sig);
        	        	output.println("the DSA signature (byte array) is " + w);
        	        	sig1 = new BigInteger(sig);
        	        	w = cryptix.util.core.BI.dumpString(sig1);
        	        	output.println("the DSA signature (BigInteger) is " + w);
        	        	BigInteger Bfirst, Bsecond;
        	        	byte[] bf = new byte[20];
        	        	int i=0, j=0, k=0;
        	        	if(sig[3]==21) j=1;
        	        	if((j==0)&&(sig[25]==21)) k=1;
        	        	else if((j==1)&&(sig[26]==21)) k=1;
        	        	output.println(" j = " + j + " k = " + k);
        	        	output.println(" sig[3] = " + sig[3] + " sig[25] = " + sig[25] + " sig[26] = " + sig[26]);
        	        	for(i=4+j;i<24+j;i++) bf[i-4-j] = sig[i];
    		Bfirst = new BigInteger(bf);
        	        	if(j==1) {byte[] bg = new byte[21];
        	        	        	        	    bg[0] = 0;
        	        	        	        	    for(i=1;i<21;i++) bg[i]=bf[i-1];
        	        	        	        	    Bfirst = new BigInteger(bg);
        	        	        	        	        	}
        	        	w = cryptix.util.core.BI.dumpString(Bfirst);
    		output.println("The first number in signature = " + w);
    		output.println(" ");
        	        	byte[] bs = new byte[20];
        	        	for(i=26+j+k;i<46+j+k;i++) bs[i-26-j-k] = sig[i];
    		Bsecond = new BigInteger(bs);
        	        	if(k==1) {byte[] bt = new byte[21];
        	        	        	        	    bt[0] = 0;
        	        	        	        	    for(i=1;i<21;i++) bt[i]=bs[i-1];
        	        	        	        	    Bsecond = new BigInteger(bt);
        	        	        	        	        	}
   	 	w = cryptix.util.core.BI.dumpString(Bsecond);
    		output.println("The second number in signature = " + w);
    		output.println(" ");
        	        	BigInteger Zero, Bhash, Bfirinv, Bsecinv, Bu1, Bu2, Ba, Bb, Bt, Bv;
        	        	Zero = new BigInteger("0");
        	        	Bhash = new BigInteger(hash);
        	        	if(Bfirst.compareTo(Zero)==-1) output.println("verify = false");
        	        	else if (Bsecond.compareTo(Zero)==-1) output.println("verify = false");
        	        	else {
        	        	        	Bsecinv = Bsecond.modInverse(q);   
        	        	        	Bu1 = Bhash.multiply(Bsecinv);
        	        	        	Bu1 = Bu1.mod(q);
        	        	        	Bu2 = Bfirst.multiply(Bsecinv);
        	        	        	Bu2 = Bu2.mod(q);
        	        	        	Ba = g.modPow(Bu1,p);
        	        	        	Bb = y.modPow(Bu2,p);
        	        	        	Bt = Ba.multiply(Bb);
        	        	        	Bt = Bt.mod(p);
        	        	        	Bv = Bt.mod(q);
        	        	        	if (Bv.compareTo(Bfirst)==0) output.println("verify (ind calculation) = true");
        	        	        	        	else output.println("verify (ind calculation) = false");
    		        	w = cryptix.util.core.BI.dumpString(Bv);
    		        	output.println("verfication number is = " + w);
    		        	output.println(" ");
        	        	        	}
        	fis = new FileInputStream(args[0]);
        	while (fis.available() != 0) {
            	b = (byte) fis.read();
                dsa.update(b);
            	};
            fis.close();
        	boolean verifies = dsa.verify(sig);
            output.println("signature verifies (verification function): " + verifies);
        	        	output.println(" ");
        	        	outFile.close();
        	        	System.out.println("File written");
    	} catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
    	}
	}
}
