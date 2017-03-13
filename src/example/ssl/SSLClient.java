package example.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

public class SSLClient {
	@SuppressWarnings("unused")
	private String trustStorePath;
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
	
	public SSLClient(String trustStorePath,  char[] passPhrase, SocketChannel sc) throws Exception {
		try
		{
			this.trustStorePath = trustStorePath;
			this.passPhrase = passPhrase;
			this.sc = sc;
			// initialized adsadsadadas
			KeyStore ks = KeyStore.getInstance("JKS"); // KeyStore Object 생성 - JKS는 Java KeyStore로 기본적인 저장 구현
			ks.load(new FileInputStream(trustStorePath),passPhrase); // keyStore 로 (경로 / 비밀번호)
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509"); // TrustManagerFactory 객체를 SunX509 알고리즘으로 생성
			tmf.init(ks); // 만들어진 KeyStore 객체로 초기화한다.
			
			sslContext = SSLContext.getInstance("TLS");  // SSLContext를 TLS알고리즘으로 생성
			sslContext.init(null, tmf.getTrustManagers(), null); 
			
			// Create SSLEngine
			sslEngine = sslContext.createSSLEngine();
			sslEngine.setUseClientMode(true);	
			sslSession = sslEngine.getSession();
			
			// Create Buffers		
			outNetBuffer = ByteBuffer.allocate(this.getNetBufferSize());
			inAppBuffer = ByteBuffer.allocate(this.getAppBufferSize());
			dummy = ByteBuffer.allocate(0);
		}
		catch(Exception e)
		{
			throw new SSLException(e);
		}
	}
	
	public void beginHandShake() throws IOException {
		sslEngine.beginHandshake();

		outNetBuffer = this.encrypt(dummy);
		
		printSSLEngineResult("HandShake - WARP");		
		
		if(sslEngineResult.getStatus() == Status.OK)
		{
			writeToSocket(outNetBuffer);
		}
		else
		{
			throw new SSLException(sslEngineResult.toString());
		}
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
				outNetBuffer.clear();
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
