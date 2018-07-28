/*
 * Copyright 2018 Jose Luis Estevez jose.estevez.prieto@gmail.com.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onixcoinj.params;

import java.io.ByteArrayOutputStream;
import org.bitcoinj.core.AltcoinBlock;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Coin;
import static org.bitcoinj.core.Coin.COIN;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.utils.MonetaryFormat;
import org.dashj.hash.X11;
import org.libdohj.core.AltcoinNetworkParameters;
import org.libdohj.core.AltcoinSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @date 13-ene-2018
 *
 * @version 1.0.0
 * @author Jose Luis Estevez jose.estevez.prieto@gmail.com
 */
public abstract class AbstractOnixcoinParams extends NetworkParameters implements AltcoinNetworkParameters {

    public static final MonetaryFormat ONIX;
    public static final MonetaryFormat MONIX;
    public static final MonetaryFormat ONIXTOSHI;

    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1079
    public static final int ONIX_TARGET_TIMESPAN = (int) (24 * 60 * 60);

    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1080
    public static final int ONIX_TARGET_SPACING = (int) (3 * 60);

    public static final int ONIX_INTERVAL = ONIX_TARGET_TIMESPAN / ONIX_TARGET_SPACING;

    public static final long MAX_ONIXCOINS = 1200000000; // TODO: Verificar este valor!

    public static final Coin MAX_ONIXCOIN_MONEY = COIN.multiply(MAX_ONIXCOINS);

    public static final String CODE_ONIX = "ONX";
    /**
     * Currency code for base 1/1,000
     */
    public static final String CODE_MONIX = "mONIX";
    /**
     * Currency code for base 1/100,000,000
     */
    public static final String CODE_ONIXTOSHI = "onixtoshi";

    static {
        ONIX = MonetaryFormat.BTC.noCode()
                .code(0, CODE_ONIX)
                .code(3, CODE_MONIX)
                .code(7, CODE_ONIXTOSHI);
        MONIX = ONIX.shift(3).minDecimals(2).optionalDecimals(2);
        ONIXTOSHI = ONIX.shift(7).minDecimals(0).optionalDecimals(2);
    }

    /**
     * The string returned by getId() for the main, production network where
     * people trade things.
     */
    public static final String ID_ONIX_MAINNET = "info.onixcoin.production";
    /**
     * The string returned by getId() for the testnet.
     */
    public static final String ID_ONIX_TESTNET = "info.onixcoin.test";
    /**
     * The string returned by getId() for regtest.
     */
    public static final String ID_ONIX_REGTEST = "regtest";

    public static final int ONIXCOIN_PROTOCOL_VERSION_MINIMUM = 70010;
    public static final int ONIXCOIN_PROTOCOL_VERSION_CURRENT = 70010;

    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1068
    private static final Coin BASE_SUBSIDY = COIN.multiply(60);

    protected Logger log = LoggerFactory.getLogger(AbstractOnixcoinParams.class);

    public AbstractOnixcoinParams() {
        super();
        interval = ONIX_INTERVAL;
        targetTimespan = ONIX_TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1e0fffffL); // TODO: figure out the Onixcoin value of this

    }
    

    @Override
    public Coin getBlockSubsidy(final int height) {
        return BASE_SUBSIDY.shiftRight(height / getSubsidyDecreaseBlockCount());
    }

    public MonetaryFormat getMonetaryFormat() {
        return ONIX;
    }

    @Override
    public Coin getMaxMoney() {
        return MAX_ONIXCOIN_MONEY;
    }

    @Override
    public Coin getMinNonDustOutput() {
        return Coin.COIN;
    }

    @Override
    public String getUriScheme() {
        return "onixcoin";
    }

    @Override
    public boolean hasMaxMoney() {
        return true;
    }

    /**
     * Whether this network has special rules to enable minimum difficulty
     * blocks after a long interval between two blocks (i.e. testnet).
     */
    public abstract boolean allowMinDifficultyBlocks();

    /**
     * Get the POW hash to use for a block. Dash uses X11, which is also the
     * same as the block hash.
     */
    @Override
    public Sha256Hash getBlockDifficultyHash(Block block) {
        return block.getHash();
    }

    /**
     * Get the hash to use for a block. Most coins use SHA256D for block hashes,
     * but ONIX uses X11.
     */
    @Override
    public boolean isBlockHashSHA256D() {
        return false;
    }

    @Override
    public Sha256Hash calculateBlockHash(byte[] payload, int offset, int length) {
        return Sha256Hash.wrapReversed(X11.digest(payload, offset, length));
    }

    @Override
    public AltcoinSerializer getSerializer(boolean parseRetain) {
        return new AltcoinSerializer(this, parseRetain);
    }
    @Override
    public abstract void checkDifficultyTransitions(StoredBlock sb, Block block, BlockStore bs) throws VerificationException, BlockStoreException;
    
    
    public abstract String getTrustPeer();
}
