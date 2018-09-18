package my.encrypterz.com;

import java.io.BufferedReader;
import java.io.InputStreamReader;


public class binarytodec {




public static void main(String[] args) throws Exception {
	
	String g="10011111000000111000111";
	


	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
    System.out.println("Enter the binary value:");
     String s = null;
	
		s = br.readLine();
	
    System.out.println("Decimal value is : "+Integer.parseInt(s, 2));

}
}