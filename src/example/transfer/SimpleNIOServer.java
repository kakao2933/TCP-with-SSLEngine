package example.transfer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import example.ssl.SSLServer;
import example.util.Util;


public class SimpleNIOServer {

	private static final int PORT = 9090;
	
	private static final String keyStore = "keystore/server/SimpleNIOServer.keystore";
	private static final String storepass = "example";
	
	private Selector selector = null;
	private ServerSocketChannel serverSocketChannel = null;
	private ServerSocket serverSocket = null;
	
	private ConcurrentHashMap<SocketChannel, SSLServer> sslServerMap = null;
	
	public SimpleNIOServer()
	{
		initServer();
	}
	
	public void initServer()
	{
		try
		{
			selector = Selector.open();
			serverSocketChannel = ServerSocketChannel.open();
			serverSocketChannel.configureBlocking(false);
			serverSocket = serverSocketChannel.socket();
			InetSocketAddress isa = new InetSocketAddress(PORT);
			serverSocket.bind(isa);
			
			serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
			
			sslServerMap = new ConcurrentHashMap<SocketChannel, SSLServer>();
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
	}
	
	public void startServer()
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
					
					if(key.isAcceptable())
					{
						accept(key);
					}
					else if(key.isReadable())
					{
						read(key);
					}
					it.remove();
				}
			}
		}
		catch(ClosedSelectorException e)
		{
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			
		}
	}
	
	private void accept(SelectionKey key)
	{
		ServerSocketChannel server = (ServerSocketChannel)key.channel();
		SocketChannel sc;
		
		try
		{
			sc = server.accept();
			sc.configureBlocking(false);
			sc.register(selector, SelectionKey.OP_READ);

			SSLServer sslServer = new SSLServer(keyStore, storepass.toCharArray(), sc);
			sslServerMap.put(sc, sslServer);
			sslServer.beginHandShake();			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	private void read(SelectionKey key)
	{
		SocketChannel sc = (SocketChannel)key.channel();

		ByteBuffer buffer = ByteBuffer.allocate(1024);
		
		try
		{
			SSLServer sslServer = sslServerMap.get(sc);
			if(sslServer.getHandShakeStatus() != HandshakeStatus.NOT_HANDSHAKING
					&& sslServer.getHandShakeStatus() != HandshakeStatus.FINISHED)
			{
					sslServer.handshake(sc);
			}
			else
			{
				if(sc.read(buffer) > 0)
				{
					buffer.flip();
					Util.log("[Client Message]" ,sslServer.decrypt(buffer));
					sc.write(sslServer.encrypt(ByteBuffer.wrap("Hi! Client~!".getBytes())));
				}
				else
				{
					sslServer.closeInbound();					
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
		try
		{
			SSLServer sslServer = sslServerMap.get(sc);
			sslServer.closeOutbound();
			sslServerMap.remove(sc);
			
			if(sc != null) sc.close();		
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		System.out.println("Running Server...");
		SimpleNIOServer server = new SimpleNIOServer();
		server.startServer();
	}
}
