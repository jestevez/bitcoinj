package org.bitcoinj.core;

/**
 * Created by Hash Engineering on 6/26/2017.
 *
 * This is a wrapper to allow a message to be ignored that bitcoinj
 * will not process.  This will prevent the peer from being rejected.
 */
public class IgnoreThisMessage extends EmptyMessage {

    public IgnoreThisMessage(NetworkParameters params) {
        super(params);
        length = 0;
    }
}
