package example.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class SSLServer  {
	@SuppressWarnings("unused")
	private String keyStorePath;
	@SuppressWarnings("unused")
	private char[] passPhrase;
	
	private SSLEngine sslEngine;
	private SSLContext sslContext;
	private SSLSession sslSession;
	private SSLEngineResult sslEngineResult;

	private SocketChannel sc;
	
	private ByteBuffer outNetBuffer;
	private ByteBuffer inAppBuffer;
	private ByteBuffer dummy;
	
	public SSLServer(String keyStorePath, char[] passPhrase, SocketChannel sc) throws Exception{
		try
		{
			this.keyStorePath = keyStorePath;
			this.passPhrase = passPhrase;
			this.sc = sc;	
			
			// initialize
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(keyStorePath),passPhrase);
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks,passPhrase);
			
			sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), null, null);
			
			// Create SSLEngine
			sslEngine = sslContext.createSSLEngine();
			sslEngine.setUseClientMode(false);
			sslSession = sslEngine.getSession();
			
			// Create Buffers
			dummy = ByteBuffer.allocate(0);
			outNetBuffer = ByteBuffer.allocate(this.getNetBufferSize());
			inAppBuffer = ByteBuffer.allocate(this.getAppBufferSize());
		}
		catch(Exception e)
		{
			throw new SSLException(e);
		}
	}
	
	/**
	 * Initiates handshaking (initial or renegotiation) on this SSLServer. 
	 * @throws IOException
	 */		
	public void beginHandShake() throws SSLException {
		sslEngine.beginHandshake();
		printSSLEngineResult("HandShake");
	}
	
	public void handshake(SocketChannel sc) throws SSLException,IOException {
		
		ByteBuffer buff = ByteBuffer.allocate(this.getNetBufferSize());
		
		while(sc.read(buff) > 0);
		
		buff.flip();		
		
		while(buff.hasRemaining())
		{
			// unwrap
			inAppBuffer = this.decrypt(buff);
			printSSLEngineResult("UNWRAP");
			
			// task
			if(this.getHandShakeStatus() == HandshakeStatus.NEED_TASK)
			{
				doTask();
				printSSLEngineResult("TASK");		
			}
			
			// wrap
			while(this.getHandShakeStatus() == HandshakeStatus.NEED_WRAP)
			{			
				dummy.rewind();
				outNetBuffer = this.encrypt(dummy);
				printSSLEngineResult("WRAP");
				writeToSocket(outNetBuffer);
			}
		}
	}
	public HandshakeStatus getHandShakeStatus() {
		return sslEngine.getHandshakeStatus();
	}
	public synchronized ByteBuffer encrypt(ByteBuffer buffer) throws SSLException {
		outNetBuffer.clear();
		sslEngineResult = sslEngine.wrap(buffer, outNetBuffer);
		
		printSSLEngineResult("encrypt");			
		
		outNetBuffer.flip();
		return outNetBuffer;
	}

	public synchronized ByteBuffer decrypt(ByteBuffer buffer) throws SSLException {
		inAppBuffer.clear();
		sslEngineResult = sslEngine.unwrap(buffer, inAppBuffer);

		printSSLEngineResult("decrypt");			
		
		inAppBuffer.flip();
		return inAppBuffer;
	}
	
	public int getNetBufferSize() {
		return sslSession.getPacketBufferSize();
	}
	
	public int getAppBufferSize() {
		return sslSession.getApplicationBufferSize();
	}
	
	private void doTask() {
		Runnable task;
		
		while((task = sslEngine.getDelegatedTask()) != null)
		{
			task.run();
		}
	}

	public void closeInbound() throws SSLException
	{
		sslEngine.closeInbound();
	}
	
	public void closeOutbound()
	{
		sslEngine.closeOutbound();
	}	
	
	private void printSSLEngineResult(String str)
	{
		if(sslEngineResult == null) return;
//		Util.log("============================================================================================");
//		Util.log(str);
//		Util.log("============================================================================================");
//		Util.log("Status=" + sslEngineResult.getStatus() + "  bytesConsumed=" + sslEngineResult.bytesConsumed() + " bytesProduced=" + sslEngineResult.bytesProduced());
//		Util.log(sslEngineResult.toString());
	}	
	
	private void writeToSocket(ByteBuffer buff) throws IOException
	{
		while(buff.hasRemaining())
		{
			sc.write(buff);
		}
	}	
}
