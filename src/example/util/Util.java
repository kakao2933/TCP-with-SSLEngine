package example.util;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

public class Util {

	public static String bufferToString(ByteBuffer buff)
	{
		Charset charset = Charset.forName("UTF-8");
		CharsetDecoder decoder = charset.newDecoder();
		
		String message = "";
		
		try
		{
			message = decoder.decode(buff).toString();
		}
		catch (Exception e) {
			message = e.getMessage();
		}
		
		return message;
	}
	
	public static void log(String str)
	{
		System.out.println(str);
	}
	
	public static void log(String str , ByteBuffer buff)
	{
		log(str + bufferToString(buff));
	}	
}
