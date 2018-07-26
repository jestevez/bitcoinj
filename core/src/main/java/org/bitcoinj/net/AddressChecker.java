package org.bitcoinj.net;

import org.bitcoinj.utils.CIDRUtils;

import java.net.InetAddress;

/**
 * Created by danda on 1/12/17.
 */
public class AddressChecker {

    private CIDRUtils onionCatNet;
    private CIDRUtils rfc4193Net;

    public AddressChecker() {

        // Note:  this is borrowed/ported from btcd (written in go).

        // btcd has many more rules that are probably important and should be
        // implemented in this class, but for now we only care about onion
        // addresses for onioncat (ipv6) encoding/decoding.

        // onionCatNet defines the IPv6 address block used to support Tor.
        // bitcoind encodes a .onion address as a 16 byte number by decoding the
        // address prior to the .onion (i.e. the key hash) base32 into a ten
        // byte number. It then stores the first 6 bytes of the address as
        // 0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43.
        //
        // This is the same range used by OnionCat, which is part part of the
        // RFC4193 unique local IPv6 range.
        //
        // In summary the format is:
        // { magic 6 bytes, 10 bytes base32 decode of key hash }
        onionCatNet = new CIDRUtils("fd87:d87e:eb43::", 48);

        // rfc4193Net specifies the IPv6 unique local address block as defined
        // by RFC4193 (FC00::/7).
        rfc4193Net = new CIDRUtils("FC00::", 7);
    }

    // IsValid returns whether or not the passed address is valid.  The address is
    // considered invalid under the following circumstances:
    // IPv4: It is either a zero or all bits set address.
    // IPv6: It is either a zero or RFC3849 documentation address.
    public boolean IsValid(InetAddress addr) {
        // todo:  port/implement.

        // IsUnspecified returns if address is 0, so only all bits set, and
        // RFC3849 need to be explicitly checked.

        // return na.IP != nil && !(na.IP.IsUnspecified() ||
        //    na.IP.Equal(net.IPv4bcast))

        return true;
    }

    // IsOnionCatTor returns whether or not the passed address is in the IPv6 range
    // used by bitcoin to support Tor (fd87:d87e:eb43::/48).  Note that this range
    // is the same range used by OnionCat, which is part of the RFC4193 unique local
    // IPv6 range.
    public boolean IsOnionCatTor(InetAddress addr) {
        return onionCatNet.isInRange(addr);
    }

    // IsRFC4193 returns whether or not the passed address is part of the IPv6
    // unique local range as defined by RFC4193 (FC00::/7).
    public boolean IsRFC4193(InetAddress addr) {
        return rfc4193Net.isInRange(addr);
    }

}
