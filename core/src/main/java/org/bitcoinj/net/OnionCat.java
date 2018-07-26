package org.bitcoinj.net;

import org.bitcoinj.utils.Base32;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;


/**
 * Created by danda on 1/12/17.
 */
public class OnionCat {

    /** Converts a .onion address to onioncat format
     *
     * @param hostname
     * @return
     */
    public static byte[] onionHostToIPV6Bytes(String hostname) {
        String needle = ".onion";
        if( hostname.endsWith(needle) ) {
            hostname = hostname.substring(0,hostname.length() - needle.length());
        }
        byte[] prefix = new byte[] {(byte)0xfd, (byte)0x87, (byte)0xd8, (byte)0x7e, (byte)0xeb, (byte)0x43};
        byte[] onionaddr = Base32.base32Decode(hostname);
        byte[] ipBytes = new byte[prefix.length + onionaddr.length];
        System.arraycopy(prefix, 0, ipBytes, 0, prefix.length);
        System.arraycopy(onionaddr, 0, ipBytes, prefix.length, onionaddr.length);

        return ipBytes;
    }

    public static InetAddress onionHostToInetAddress(String hostname) throws UnknownHostException {
        return InetAddress.getByAddress(onionHostToIPV6Bytes(hostname));
    }

    public static InetSocketAddress onionHostToInetSocketAddress(String hostname, int port) throws UnknownHostException {
        return new InetSocketAddress( onionHostToInetAddress(hostname), port);
    }


    /** Converts an IPV6 onioncat encoded address to a hostname
     *
     * @param bytes
     * @return
     */
    public static String IPV6BytesToOnionHost( byte[] bytes) {
        String base32 = Base32.base32Encode( Arrays.copyOfRange(bytes, 6, 16) );
        return base32.toLowerCase() + ".onion";
    }
}
