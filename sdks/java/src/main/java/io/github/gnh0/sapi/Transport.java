package io.github.gnh0.sapi;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.*;

/** Bounded Java 8 HTTP transport. Connections and custom TLS trust are scoped per request. */
final class Transport {
    private Transport() {}
    private static final ThreadPoolExecutor WORKERS=new ThreadPoolExecutor(4,4,30,TimeUnit.SECONDS,new ArrayBlockingQueue<Runnable>(32),r->{Thread t=new Thread(r,"sapi-http");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private static final ThreadPoolExecutor CLEANUP=new ThreadPoolExecutor(4,4,30,TimeUnit.SECONDS,new ArrayBlockingQueue<Runnable>(32),r->{Thread t=new Thread(r,"sapi-http-cleanup");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    static final class Response {final int status;final byte[] body;Response(int status,byte[] body){this.status=status;this.body=body;}}
    static Response post(URI url,byte[] body,String type,String accept,int limit,SSLContext tls,Duration timeout) throws Exception {
        long millis=timeout.toMillis();if(millis<1||millis>120000)throw new IllegalArgumentException("timeout must be 1..120000 ms");
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(millis);
        AtomicReference<HttpURLConnection> connection=new AtomicReference<>();
        Future<Response> pending=WORKERS.submit(()->{
            HttpURLConnection c=(HttpURLConnection)url.toURL().openConnection();connection.set(c);
            try {
                if(c instanceof HttpsURLConnection && tls!=null)((HttpsURLConnection)c).setSSLSocketFactory(tls.getSocketFactory());
                // Preserve the platform's HTTPS endpoint identification. No permissive hostname verifier.
                c.setInstanceFollowRedirects(false);c.setConnectTimeout(remaining(deadline));c.setReadTimeout(remaining(deadline));
                c.setRequestMethod("POST");c.setDoOutput(true);c.setFixedLengthStreamingMode(body.length);c.setRequestProperty("Content-Type",type);c.setRequestProperty("Accept",accept);c.setRequestProperty("Connection","close");
                try(OutputStream output=c.getOutputStream()){output.write(body);}
                c.setReadTimeout(remaining(deadline));int status=c.getResponseCode();
                String content=c.getHeaderField("Content-Type");
                if(content==null||!content.split(";")[0].equals(accept)||c.getHeaderField("Content-Encoding")!=null)throw new SapiException("transport_error");
                long declared=c.getContentLengthLong();if(declared>limit)throw new SapiException("transport_error");
                InputStream source=status<400?c.getInputStream():c.getErrorStream();if(source==null)throw new SapiException("transport_error");
                try(InputStream input=source;ByteArrayOutputStream bytes=new ByteArrayOutputStream()) {
                    byte[] buffer=new byte[8192];
                    while(true){c.setReadTimeout(remaining(deadline));int n=input.read(buffer);if(n<0)break;if(bytes.size()+n>limit)throw new SapiException("transport_error");bytes.write(buffer,0,n);}
                    if(declared>=0&&declared!=bytes.size())throw new SapiException("transport_error");
                    remaining(deadline);return new Response(status,bytes.toByteArray());
                }
            } finally {c.disconnect();}
        });
        try{return pending.get(remaining(deadline),TimeUnit.MILLISECONDS);}
        catch(Exception e){
            pending.cancel(true);WORKERS.remove((Runnable)pending);HttpURLConnection c=connection.get();
            // Java 8 disconnect may wait on a blocked body reader's monitor. Never wait here.
            if(c!=null)try{CLEANUP.execute(c::disconnect);}catch(RejectedExecutionException full){/* The worker's finally also closes it. */}
            throw e;
        }
    }
    private static int remaining(long deadline) throws SocketTimeoutException {
        long nanos=deadline-System.nanoTime();if(nanos<=0)throw new SocketTimeoutException("deadline");return (int)Math.max(1,TimeUnit.NANOSECONDS.toMillis(nanos));
    }
}
