package util.http;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import util.ExecutionEnvironment;

import javax.net.ssl.SSLParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DOHHttp2Util {

    // ---- HPACK helpers (simplified for demonstration) ----

    static byte[] hpackIndexed(int index) {
        return new byte[]{(byte) (0x80 | index)};
    }

    static byte[] hpackLiteral(String name, String value) throws Exception {
        byte[] nameBytes = name.getBytes(StandardCharsets.US_ASCII);
        byte[] valueBytes = value.getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x40); // Literal Header Field with Incremental Indexing
        out.write(nameBytes.length); // NOTE: real HPACK uses varint, this is simplified
        out.write(nameBytes);
        out.write(valueBytes.length); // NOTE: real HPACK uses varint, this is simplified
        out.write(valueBytes);
        return out.toByteArray();
    }

    // ---- DNS wire-format helpers ----

    static byte[] buildDnsQuery(String qname, int qtype) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        writeU16(out, 0x1234);   // ID
        writeU16(out, 0x0100);   // Flags: standard query, RD=1
        writeU16(out, 1);        // QDCOUNT
        writeU16(out, 0);        // ANCOUNT
        writeU16(out, 0);        // NSCOUNT
        writeU16(out, 0);        // ARCOUNT
        // QNAME
        for (String label : qname.split("\\.")) {
            byte[] lb = label.getBytes(StandardCharsets.US_ASCII);
            out.write(lb.length);
            out.write(lb);
        }
        out.write(0x00);         // root label
        // QTYPE, QCLASS=IN(1)
        writeU16(out, qtype);
        writeU16(out, 1);
        return out.toByteArray();
    }

    static void writeU16(ByteArrayOutputStream out, int v) {
        out.write((v >> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    static int readU16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    static class DnsAnswer {
        String name;
        int type;
        int clazz;
        int ttl;
        byte[] rdata;

        @Override
        public String toString() {
            if (type == 1 && rdata != null && rdata.length == 4) { // A
                return name + " A " + (rdata[0] & 0xFF) + "." + (rdata[1] & 0xFF) + "." +
                        (rdata[2] & 0xFF) + "." + (rdata[3] & 0xFF) + " TTL=" + ttl;
            }
            if (type == 28 && rdata != null && rdata.length == 16) { // AAAA
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 16; i += 2) {
                    int seg = ((rdata[i] & 0xFF) << 8) | (rdata[i + 1] & 0xFF);
                    sb.append(Integer.toHexString(seg));
                    if (i < 14) sb.append(':');
                }
                return name + " AAAA " + sb + " TTL=" + ttl;
            }
            return name + " TYPE=" + type + " RDLEN=" + (rdata == null ? 0 : rdata.length) + " TTL=" + ttl;
        }
    }

    static String readName(byte[] msg, int[] offRef) {
        int off = offRef[0];
        StringBuilder sb = new StringBuilder();
        int jumpedOff = -1;
        boolean jumped = false;
        while (true) {
            int len = msg[off] & 0xFF;
            if ((len & 0xC0) == 0xC0) {
                // pointer
                int ptr = ((len & 0x3F) << 8) | (msg[off + 1] & 0xFF);
                if (!jumped) {
                    jumpedOff = off + 2;
                    jumped = true;
                }
                off = ptr;
                continue;
            }
            off++;
            if (len == 0) {
                break;
            }
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < len; i++) {
                sb.append((char) (msg[off + i] & 0xFF));
            }
            off += len;
        }
        offRef[0] = jumped ? jumpedOff : off;
        return sb.toString();
    }

    static List<DnsAnswer> parseDnsResponse(byte[] msg) {
        List<DnsAnswer> answers = new ArrayList<>();
        if (msg.length < 12) return answers;
        int off = 0;
        int id = readU16(msg, off);
        off += 2;
        int flags = readU16(msg, off);
        off += 2;
        int qd = readU16(msg, off);
        off += 2;
        int an = readU16(msg, off);
        off += 2;
        int ns = readU16(msg, off);
        off += 2;
        int ar = readU16(msg, off);
        off += 2;
        // skip questions
        for (int i = 0; i < qd; i++) {
            int[] o = new int[]{off};
            readName(msg, o);
            off = o[0];
            off += 4; // QTYPE+QCLASS
        }
        // answers
        for (int i = 0; i < an; i++) {
            int[] o = new int[]{off};
            String name = readName(msg, o);
            off = o[0];
            int type = readU16(msg, off);
            off += 2;
            int clazz = readU16(msg, off);
            off += 2;
            int ttl = ((msg[off] & 0xFF) << 24) | ((msg[off + 1] & 0xFF) << 16)
                    | ((msg[off + 2] & 0xFF) << 8) | (msg[off + 3] & 0xFF);
            off += 4;
            int rdlen = readU16(msg, off);
            off += 2;
            if (off + rdlen > msg.length) rdlen = Math.max(0, msg.length - off);
            byte[] rdata = new byte[rdlen];
            System.arraycopy(msg, off, rdata, 0, rdlen);
            off += rdlen;
            DnsAnswer a = new DnsAnswer();
            a.name = name;
            a.type = type;
            a.clazz = clazz;
            a.ttl = ttl;
            a.rdata = rdata;
            answers.add(a);
        }
        return answers;
    }

    // ---- HTTP/2 framing helpers ----

    static void writeFrameHeader(ByteArrayOutputStream out, int length, int type, int flags, int streamId) {
        out.write((length >> 16) & 0xFF);
        out.write((length >> 8) & 0xFF);
        out.write(length & 0xFF);
        out.write(type & 0xFF);
        out.write(flags & 0xFF);
        out.write((streamId >> 24) & 0x7F); // clear MSB (R bit)
        out.write((streamId >> 16) & 0xFF);
        out.write((streamId >> 8) & 0xFF);
        out.write(streamId & 0xFF);
    }

    static boolean readFully(InputStream in, byte[] buf, int len) throws Exception {
        int off = 0;
        while (off < len) {
            int r = in.read(buf, off, len - off);
            if (r == -1) return false;
            off += r;
        }
        return true;
    }

    // ---- Connection bootstrap (once) ----

    static SSLSocket openHttp2Socket(InetSocketAddress sadr, int timeout) throws Exception {
        SSLContext sslContext = SSLContext.getDefault();
        Socket socket = SocketChannel.open().socket();
        ExecutionEnvironment.getEnvironment().protectSocket(socket, 0);
        socket.connect(sadr, timeout);
        SSLSocket sslsocket = (SSLSocket) sslContext.getSocketFactory().createSocket(socket, sadr.getHostName(), sadr.getPort(), true);
        SSLParameters params = sslsocket.getSSLParameters();
        params.setApplicationProtocols(new String[]{"h2"});
        sslsocket.setSSLParameters(params);

        sslsocket.startHandshake();
        String negotiated = sslsocket.getApplicationProtocol();
        if (!"h2".equals(negotiated)) {
            throw new IllegalStateException("HTTP/2 not negotiated; got: " + negotiated);
        }

        OutputStream out = sslsocket.getOutputStream();
        InputStream in = sslsocket.getInputStream();

        // Client preface
        out.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII));

        // SETTINGS (empty)
        out.write(new byte[]{
                0x00, 0x00, 0x00, // length
                0x04,           // type = SETTINGS
                0x00,           // flags
                0x00, 0x00, 0x00, 0x00 // stream id
        });
        out.flush();

        // Read initial server SETTINGS and ACK them
        // Minimal loop: read frames until we see a SETTINGS from stream 0, then ACK
        boolean acked = false;
        for (int i = 0; i < 4 && !acked; i++) { // small bound to avoid hanging
            byte[] header = new byte[9];
            if (!readFully(in, header, 9)) break;
            int flen = ((header[0] & 0xFF) << 16) | ((header[1] & 0xFF) << 8) | (header[2] & 0xFF);
            int ftype = header[3] & 0xFF;
            int streamId = ((header[5] & 0x7F) << 24) | ((header[6] & 0xFF) << 16) | ((header[7] & 0xFF) << 8) | (header[8] & 0xFF);
            if (flen > 0) {
                byte[] payload = new byte[flen];
                if (!readFully(in, payload, flen)) break;
            }
            if (streamId == 0 && ftype == 0x04) {
                // Send SETTINGS ACK
                ByteArrayOutputStream ack = new ByteArrayOutputStream();
                writeFrameHeader(ack, 0, 0x04, 0x01, 0);
                out.write(ack.toByteArray());
                out.flush();
                acked = true;
            }
        }

        return sslsocket;
    }

    static Integer hpackIndexedStatus(int index) {
        switch (index) {
            case 8:
                return 200;
            case 9:
                return 204;
            case 10:
                return 206;
            case 11:
                return 304;
            case 12:
                return 400;
            case 13:
                return 404;
            case 14:
                return 500;
            default:
                return null;
        }
    }


    // ---- Send a single DNS query on a given stream and return parsed answers ----
    public static byte[] sendDnsQuery(InetSocketAddress sadr, String path, byte[] dnsQuery, int offs, int length, int timeout) throws Exception {

        SSLSocket socket = openHttp2Socket(sadr, timeout);
        try {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // valid client stream IDs all odd numbers from 1-2^31-1 (1-2147483647) growing order.
            int streamId = 1;

            // HPACK header block
            ByteArrayOutputStream hpack = new ByteArrayOutputStream();
            hpack.write(hpackIndexed(3)); // :method POST
            hpack.write(hpackIndexed(7)); // :scheme https
            hpack.write(hpackLiteral(":authority", sadr.getHostName()));
            hpack.write(hpackLiteral(":path", path));
            hpack.write(hpackLiteral("content-type", "application/dns-message"));
            hpack.write(hpackLiteral("accept", "application/dns-message"));
            hpack.write(hpackLiteral("content-length", Integer.toString(length)));
            byte[] headerBlock = hpack.toByteArray();

            // HEADERS (END_HEADERS)
            ByteArrayOutputStream headersFrame = new ByteArrayOutputStream();
            writeFrameHeader(headersFrame, headerBlock.length, 0x01, 0x04, streamId);
            headersFrame.write(headerBlock);
            out.write(headersFrame.toByteArray());
            out.flush();

            // DATA (END_STREAM)
            ByteArrayOutputStream dataFrame = new ByteArrayOutputStream();
            writeFrameHeader(dataFrame, length, 0x00, 0x01, streamId);
            dataFrame.write(dnsQuery, offs, length);
            out.write(dataFrame.toByteArray());
            out.flush();

            // Read response frames
            ByteArrayOutputStream responseBody = new ByteArrayOutputStream();
            boolean done = false;
            int httpStatus = -1;

            while (!done) {
                byte[] header = new byte[9];
                if (!readFully(in, header, 9))
                    break;

                int flen = ((header[0] & 0xFF) << 16) | ((header[1] & 0xFF) << 8) | (header[2] & 0xFF);
                int ftype = header[3] & 0xFF;
                int fflags = header[4] & 0xFF;
                int sid = ((header[5] & 0x7F) << 24) | ((header[6] & 0xFF) << 16) | ((header[7] & 0xFF) << 8)
                        | (header[8] & 0xFF);

                byte[] payload = new byte[flen];
                if (flen > 0 && !readFully(in, payload, flen))
                    break;

                if (sid == 0 && ftype == 0x04) {
                    // SETTINGS mid-stream ACK
                    ByteArrayOutputStream ack = new ByteArrayOutputStream();
                    writeFrameHeader(ack, 0, 0x04, 0x01, 0);
                    out.write(ack.toByteArray());
                    out.flush();
                    continue;
                }

                if (sid != streamId) {
                    continue; // ignore other streams
                }

                if (ftype == 0x01) { // HEADERS
                    int p = 0;

                    while (p < payload.length) {
                        int b = payload[p] & 0xFF;

                        // 1) Indexed Header Field (1xxxxxxx)
                        if ((b & 0x80) != 0) {
                            int index = b & 0x7F;
                            Integer s = hpackIndexedStatus(index);
                            if (s != null) {
                                httpStatus = s;
                            }
                            p++; // nur ein Byte in dieser simplen Variante
                            continue;
                        }

                        // 2) Literal Header Field with Incremental Indexing (01xxxxxx)
                        if ((b & 0x40) != 0) {
                            p++;

                            if (p >= payload.length)
                                break;
                            int nameLen = payload[p++] & 0xFF;
                            if (p + nameLen > payload.length)
                                break;
                            String name = new String(payload, p, nameLen, StandardCharsets.US_ASCII);
                            p += nameLen;

                            if (p >= payload.length)
                                break;
                            int valLen = payload[p++] & 0xFF;
                            if (p + valLen > payload.length)
                                break;
                            String value = new String(payload, p, valLen, StandardCharsets.US_ASCII);
                            p += valLen;

                            if (name.equals(":status")) {
                                try {
                                    httpStatus = Integer.parseInt(value.trim());
                                } catch (Exception ignored) {
                                }
                            }

                            continue;
                        }

                        // 3) Alles andere (Huffman, andere Literal-Typen, etc.) ignorieren wir in
                        // dieser Minimalversion
                        break;
                    }

                    // --- Error Handling ---
                    if (httpStatus != -1 && httpStatus != 200) {
                        throw new IllegalStateException(
                                "DoH server returned HTTP status " + httpStatus + " on stream " + streamId);
                    }

                    if ((fflags & 0x01) != 0) { // END_STREAM
                        done = true;
                    }
                } else if (ftype == 0x00) { // DATA
                    responseBody.write(payload);
                    if ((fflags & 0x01) != 0) {
                        done = true;
                    }
                } else if (ftype == 0x03) { // RST_STREAM
                    throw new IllegalStateException("Stream " + streamId + " reset by server");
                }
            }

            byte[] resp = responseBody.toByteArray();
            socket.close();
            return resp;
        } catch (IOException e) {
            socket.close();
            throw e;
        }
    }

    // ---- Demo main: reuse one socket for two DNS queries on different streams ----

    public static void main(String[] args) throws Exception {

        int port = 443;
        String host = "dns.google";
        InetAddress iadr = InetAddress.getByName(host);
        InetSocketAddress sadr = new InetSocketAddress(iadr, port);
        //String host = "dns.mullvad.net";
        //String host = "dns.cloudflare.com";
        //String host = "dns.quad9.net";

        try {

            // valid client stream IDs all odd numbers from 1-2^31-1 (1-2147483647) growing order.

            // First request on stream 1: www.example.com A
            byte[] dnsQuery = buildDnsQuery("www.zenz-solutions.de", 1);
            List<DnsAnswer> answers1 = parseDnsResponse(sendDnsQuery(sadr,"/dns-query", dnsQuery, 0, dnsQuery.length, 0));
            System.out.println("Results for www.example.com:");
            if (answers1.isEmpty()) {
                System.out.println("  No answers parsed.");
            } else {
                for (DnsAnswer a : answers1) {
                    System.out.println("  " + a);
                }
            }
            
            /*

            // Second request on stream 3: www.test.com A (HTTP/2 client streams use odd IDs)
            List<DnsAnswer> answers2 = sendDnsQuery(socket, host, "www.google.com", 28, 3);
            System.out.println("Results for www.google.com:");
            if (answers2.isEmpty()) {
                System.out.println("  No answers parsed.");
            } else {
                for (DnsAnswer a : answers2) {
                    System.out.println("  " + a);
                }
            }

            socket.close(); */
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
