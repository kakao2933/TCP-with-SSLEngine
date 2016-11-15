package example.transfer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;

import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import example.ssl.SSLClient;
import example.util.Util;


public class SimpleNIOClient {

	private static final String keyStore = "keystore/client/SimpleNIOClient.keystore;";
	private static final String storepass = "examples";

	private static final String HOST = "localhost"; // 연결할 주소
	private static final int PORT = 9090; // 연결할 포트

	private SocketChannel sc = null; // 소켓 채널 
	private Selector selector = null;

	private SSLClient sslClient = null; // SSL 연결 객체
	//
	public SimpleNIOClient() throws Exception // 생성자
	{
		initClient(); // 클라이언트 정립
	}

	public void initClient() throws Exception
	{
		selector = Selector.open(); // 설렉터 객체 생성
		sc = SocketChannel.open(new InetSocketAddress(HOST,PORT)); // 소켓 연결
		sc.configureBlocking(false); // 블로킹 해제
		sc.register(selector, SelectionKey.OP_READ);

		sslClient = new SSLClient(keyStore, storepass.toCharArray(), sc); // SSL클라이언트 생성 (키스토어 위치, )
		sslClient.beginHandShake(); // 핸드쉐이크 시작
	}

	public void startClient()
	{
		try
		{
			while(true)
			{
				if(selector.select() <= 0)
				{
					continue;
				}

				Iterator<SelectionKey> it = selector.selectedKeys().iterator();

				while(it.hasNext())
				{
					SelectionKey key = it.next();

					if(key.isReadable())
					{
						read(key);
					}
					it.remove();
				}				
			}
		}
		catch(Exception e)
		{

		}
	}

	private void read(SelectionKey key)
	{
		SocketChannel sc = (SocketChannel)key.channel();

		ByteBuffer buffer = ByteBuffer.allocate(1024); // ByteBuffer 객체를 생성하며, 크기를 지정한다.

		try
		{
			if(sslClient.getHandShakeStatus() != HandshakeStatus.NOT_HANDSHAKING
					&& sslClient.getHandShakeStatus() != HandshakeStatus.FINISHED)
			{
				sslClient.handshake(sc);

				if(sslClient.getHandShakeStatus() == HandshakeStatus.NOT_HANDSHAKING)
				{
					sc.write(sslClient.encrypt(ByteBuffer.wrap("Hi! Server~!".getBytes())));
				}
			}
			else
			{
				if(sc.read(buffer) > 0)
				{
					buffer.flip();
					Util.log("[Server Message]" , sslClient.decrypt(buffer));
					shutdown(sc);
				}
				else
				{
					sslClient.closeInbound();
					shutdown(sc);			
				}
			}
		}
		catch(IOException e)
		{
			shutdown(sc);
		}
	}		

	private void shutdown(SocketChannel sc)
	{
		try {
			sslClient.closeOutbound();			
			sc.close();
			selector.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}		

	public static void main(String[] args) throws Exception {
		System.out.println("Running Client...");
		SimpleNIOClient client = new SimpleNIOClient();
		client.startClient();
	}

}