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

import static com.google.common.base.Preconditions.checkState;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import org.bitcoinj.core.AltcoinBlock;
import org.bitcoinj.core.Block;
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
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.Threading;
import org.libdohj.core.AltcoinSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

/**
 * @date 18-jul-2018
 *
 * @version 1.0.0
 * @author Jose Luis Estevez jose.estevez.prieto@gmail.com
 */
public class OnixcoinTestNetParams extends AbstractOnixcoinParams {

    private static final Logger log = LoggerFactory.getLogger(OnixcoinTestNetParams.class);
    protected final ReentrantLock lock = Threading.lock("blockchain");
    public static BigInteger proofOfWorkLimit = org.bitcoinj.core.Utils.decodeCompactBits(0x1e0fffffL);  //main.cpp
    /**
     * Keeps a map of block hashes to StoredBlocks.
     */
    private final BlockStore blockStore;

    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;
    

    public OnixcoinTestNetParams() {
        super();

        id = ID_ONIX_TESTNET;
        
        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L2741
        packetMagic = 0xfec4bade;
        maxTarget = Utils.decodeCompactBits(0x1e0fffffL); 
        port = 9944;
        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/base58.h#L277
        addressHeader = 111; // PUBKEY_ADDRESS_TEST
         // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/base58.h#L278
        p2shHeader = 196; // SCRIPT_ADDRESS_TEST
        acceptableAddressCodes = new int[]{addressHeader, p2shHeader};
        dumpedPrivateKeyHeader = 239;

        
        genesisBlock = createGenesis(this);
        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L2801
        genesisBlock.setTime(1521912794L);
        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setNonce(755634);
        
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 345600;

        String genesisHash = genesisBlock.getHashAsString();

        //System.out.println(genesisHash);
        checkState(genesisHash.equals("00000c1f283092a173e73f9f318dc1ca36b02eb706adbbde5c384cd0e649849a"));
        alertSigningKey = Hex.decode("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;
        
        dnsSeeds = new String[]{
            "dnsseedt.onixcoin.info",
            "107.170.213.97" // Add @hbastidas testnet ip address testnet
        };

        bip32HeaderPub = 0x043587cf;
        bip32HeaderPriv = 0x04358394;

        checkpoints.put(0, Sha256Hash.wrap("00000c1f283092a173e73f9f318dc1ca36b02eb706adbbde5c384cd0e649849a"));
        checkpoints.put(3000, Sha256Hash.wrap("0000055235bbbc39ddaa629305018c4a46fc4b7a135a8442c02368085af32cdd"));

        blockStore = new MemoryBlockStore(this);
    }

    // Testnet Genesis block:
    // CBlock(hash=00000c1f283092a173e73f9f318dc1ca36b02eb706adbbde5c384cd0e649849a, input=01000000000000000000000000000000000000000000000000000000000000000 00000008d0b8fc93dc614ad2cdcac6bc40ea0c74dedd143c20bcada1b4a120af75cfc44da8bb65af0ff0f1eb2870b00, PoW=00000c1f283092a173e73f9f318dc1ca36b02eb706adbbde5c384cd0e649849a, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=44fc5cf70a124a1bdaca0bc243d1ed4dc7a00ec46bacdc2cad14c63dc98f0b8d, nTime=1521912794, nBits=1e0ffff0, nNonce=755634, vtx=1)
    // CTransaction(hash=64e1822ed56cd7068d031fb3a4758e79c19e3386c654066ee0a16791ab807bea, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    // CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295), coinbase 04ffff001d0104126f6e69782067656e6573697320626c6f636b)
    // CTxOut(nValue=1.00000000, scriptPubKey=04678afdb0fe5548271967f1a67130)
    // vMerkleTree: 64e1822ed56cd7068d031fb3a4758e79c19e3386c654066ee0a16791ab807bea 
    private static AltcoinBlock createGenesis(AbstractOnixcoinParams params) {
        Transaction t = new Transaction(params);
        try {
            // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L2783
            byte[] bytes = Utils.HEX.decode("04ffff001d0104126f6e69782067656e6573697320626c6f636b");
            t.addInput(new TransactionInput(params, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L2789
            Script.writeBytes(scriptPubKeyBytes, Utils.HEX.decode
                    ("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(params, t, COIN.multiply(1), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }        
        
        List<Transaction> transactions = new ArrayList<>();
        transactions.add(t);        
        AltcoinBlock genesisBlock = new AltcoinBlock(params, Block.BLOCK_VERSION_GENESIS, 
                Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000000"), 
                Sha256Hash.wrap("44fc5cf70a124a1bdaca0bc243d1ed4dc7a00ec46bacdc2cad14c63dc98f0b8d"), 
                1521912794L,
                0x1e0ffff0L, 755634, transactions);
        
        return genesisBlock;
    }

    private static OnixcoinTestNetParams instance;

    public static synchronized OnixcoinTestNetParams get() {
        if (instance == null) {
            instance = new OnixcoinTestNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return ID_ONIX_TESTNET;
    }

    @Override
    public boolean isTestNet() {
        return true;
    }

    @Override
    public boolean allowMinDifficultyBlocks() {
        return false;
    }
    
    
    @Override
    public String[] getDnsSeeds() {
         return dnsSeeds;
    }

    @Override
    public void checkDifficultyTransitions(StoredBlock sb, Block block, BlockStore bs) throws VerificationException, BlockStoreException {
        checkDifficultyTransitions(sb, block);
    }

    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1168
    private void checkDifficultyTransitions(StoredBlock storedPrev, Block nextBlock) throws BlockStoreException, VerificationException {
        final long BlocksTargetSpacing = 3 * 60;
        int TimeDaySeconds = 60 * 60 * 24;
        long PastSecondsMin = (long) (TimeDaySeconds * 3 * 0.1);
        long PastSecondsMax = (long) (TimeDaySeconds * 3 * 2.8);

        long PastBlocksMin = PastSecondsMin / BlocksTargetSpacing;
        long PastBlocksMax = PastSecondsMax / BlocksTargetSpacing;

        // storedPrev.getHeight()+1
        PastSecondsMin = (long) (TimeDaySeconds * 0.01);
        PastSecondsMax = (long) (TimeDaySeconds * 0.14);
        KimotoGravityWell(storedPrev, nextBlock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax, blockStore);

    }

    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1108
    private void KimotoGravityWell(StoredBlock storedPrev, Block nextBlock, long TargetBlocksSpacingSeconds, long PastBlocksMin, long PastBlocksMax, BlockStore blockStore) throws BlockStoreException, VerificationException {
        /* current difficulty formula, megacoin - kimoto gravity well */
        //const CBlockIndex  *BlockLastSolved				= pindexLast;
        //const CBlockIndex  *BlockReading				= pindexLast;
        //const CBlockHeader *BlockCreating				= pblock;
        StoredBlock BlockLastSolved = storedPrev;
        StoredBlock BlockReading = storedPrev;
        Block BlockCreating = nextBlock;

        BlockCreating = BlockCreating;
        long PastBlocksMass = 0;
        long PastRateActualSeconds = 0;
        long PastRateTargetSeconds = 0;
        double PastRateAdjustmentRatio = 1f;
        BigInteger PastDifficultyAverage = BigInteger.valueOf(0);
        BigInteger PastDifficultyAveragePrev = BigInteger.valueOf(0);;
        double EventHorizonDeviation;
        double EventHorizonDeviationFast;
        double EventHorizonDeviationSlow;

        long start = System.currentTimeMillis();

        if (BlockLastSolved == null || BlockLastSolved.getHeight() == 0 || (long) BlockLastSolved.getHeight() < PastBlocksMin) {
            verifyDifficulty(proofOfWorkLimit, storedPrev, nextBlock);
        }

        int i = 0;
        long LatestBlockTime = BlockLastSolved.getHeader().getTimeSeconds();

        for (i = 1; BlockReading != null && BlockReading.getHeight() > 0; i++) {
            if (PastBlocksMax > 0 && i > PastBlocksMax) {
                break;
            }
            PastBlocksMass++;

            if (i == 1) {
                PastDifficultyAverage = BlockReading.getHeader().getDifficultyTargetAsInteger();
            } else {
                PastDifficultyAverage = ((BlockReading.getHeader().getDifficultyTargetAsInteger().subtract(PastDifficultyAveragePrev)).divide(BigInteger.valueOf(i)).add(PastDifficultyAveragePrev));
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;

            PastRateActualSeconds = BlockLastSolved.getHeader().getTimeSeconds() - BlockReading.getHeader().getTimeSeconds();
            PastRateTargetSeconds = TargetBlocksSpacingSeconds * PastBlocksMass;
            PastRateAdjustmentRatio = 1.0f;

            if (PastRateActualSeconds < 0) {
                PastRateActualSeconds = 0;
            }

            if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
                PastRateAdjustmentRatio = (double) PastRateTargetSeconds / PastRateActualSeconds;
            }
            EventHorizonDeviation = 1 + (0.7084 * java.lang.Math.pow((Double.valueOf(PastBlocksMass) / Double.valueOf(28.2)), -1.228));
            EventHorizonDeviationFast = EventHorizonDeviation;
            EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

            if (PastBlocksMass >= PastBlocksMin) {
                if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
                    /*assert(BlockReading)*/;
                    break;
                }
            }
            StoredBlock BlockReadingPrev = blockStore.get(BlockReading.getHeader().getPrevBlockHash());
            if (BlockReadingPrev == null) {
                //assert(BlockReading);
                //Since we are using the checkpoint system, there may not be enough blocks to do this diff adjust, so skip until we do
                //break;
                return;
            }
            BlockReading = BlockReadingPrev;
        }

        /*CBigNum bnNew(PastDifficultyAverage);
        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            bnNew *= PastRateActualSeconds;
            bnNew /= PastRateTargetSeconds;
        } */
        //log.info("KGW-J, {}, {}, {}", storedPrev.getHeight(), i, System.currentTimeMillis() - start);
        BigInteger newDifficulty = PastDifficultyAverage;
        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            newDifficulty = newDifficulty.multiply(BigInteger.valueOf(PastRateActualSeconds));
            newDifficulty = newDifficulty.divide(BigInteger.valueOf(PastRateTargetSeconds));
        }

        if (newDifficulty.compareTo(proofOfWorkLimit) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newDifficulty.toString(16));
            newDifficulty = proofOfWorkLimit;
        }

        //log.info("KGW-j Difficulty Calculated: {}", newDifficulty.toString(16));
        verifyDifficulty(newDifficulty, storedPrev, nextBlock);

    }

    static double ConvertBitsToDouble(long nBits) {
        long nShift = (nBits >> 24) & 0xff;

        double dDiff
                = (double) 0x0000ffff / (double) (nBits & 0x00ffffff);

        while (nShift < 29) {
            dDiff *= 256.0;
            nShift++;
        }
        while (nShift > 29) {
            dDiff /= 256.0;
            nShift--;
        }

        return dDiff;
    }

    private void verifyDifficulty(BigInteger calcDiff, StoredBlock storedPrev, Block nextBlock) {
        if (calcDiff.compareTo(this.getMaxTarget()) > 0) {
            log.info("Difficulty hit proof of work limit: {}", calcDiff.toString(16));
            calcDiff = this.getMaxTarget();
        }
        int accuracyBytes = (int) (nextBlock.getDifficultyTarget() >>> 24) - 3;
        BigInteger receivedDifficulty = nextBlock.getDifficultyTargetAsInteger();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        calcDiff = calcDiff.and(mask);
//        if(this.getId().compareTo(this.ID_TESTNET) == 0)
//        {
//            if (calcDiff.compareTo(receivedDifficulty) != 0)
//                throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
//                        receivedDifficulty.toString(16) + " vs " + calcDiff.toString(16));
//        }
//        else
//        {

        int height = storedPrev.getHeight() + 1;
        if (height == 1) {
            // FIXME Falta el calculo del Bloque 1 pre-minado!
        } ///if(System.getProperty("os.name").toLowerCase().contains("windows"))
        //{
        //            if(height <= 68589)
        //            {
        //                long nBitsNext = nextBlock.getDifficultyTarget();
        //
        //                long calcDiffBits = (accuracyBytes+3) << 24;
        //                calcDiffBits |= calcDiff.shiftRight(accuracyBytes*8).longValue();
        //
        //                double n1 = ConvertBitsToDouble(calcDiffBits);
        //                double n2 = ConvertBitsToDouble(nBitsNext);
        //
        //
        //
        //
        //                if(java.lang.Math.abs(n1-n2) > n1*0.2)
        //                              throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
        //                                receivedDifficulty.toString(16) + " vs " + calcDiff.toString(16));
        //
        //
        //            }
        else {
            if (calcDiff.compareTo(receivedDifficulty) != 0) {
                throw new VerificationException("[BLOCK " + height + "] Network provided difficulty bits do not match what was calculated: "
                        + receivedDifficulty.toString(16) + " vs " + calcDiff.toString(16));
            }
        }

//        }
    }

    private void checkTestnetDifficulty(StoredBlock storedPrev, Block prev, Block next) throws VerificationException, BlockStoreException {
        checkState(lock.isHeldByCurrentThread());
        // After 15th February 2012 the rules on the testnet change to avoid people running up the difficulty
        // and then leaving, making it too hard to mine a block. On non-difficulty transition points, easy
        // blocks are allowed if there has been a span of 20 minutes without one.
        final long timeDelta = next.getTimeSeconds() - prev.getTimeSeconds();
        // There is an integer underflow bug in bitcoin-qt that means mindiff blocks are accepted when time
        // goes backwards.
        if (timeDelta >= 0 && timeDelta > NetworkParameters.TARGET_SPACING * 2) {
            if (next.getDifficultyTargetAsInteger().equals(this.getMaxTarget())) {
                return;
            } else {
                throw new VerificationException("Unexpected change in difficulty");
            }
        } else {
            // Walk backwards until we find a block that doesn't have the easiest proof of work, then check
            // that difficulty is equal to that one.
            StoredBlock cursor = storedPrev;
            while (!cursor.getHeader().equals(this.getGenesisBlock())
                    && cursor.getHeight() % this.getInterval() != 0
                    && cursor.getHeader().getDifficultyTargetAsInteger().equals(this.getMaxTarget())) {
                cursor = cursor.getPrev(blockStore);
            }
            BigInteger cursorTarget = cursor.getHeader().getDifficultyTargetAsInteger();
            BigInteger newTarget = next.getDifficultyTargetAsInteger();
            if (!cursorTarget.equals(newTarget)) {
                throw new VerificationException("Testnet block transition that is not allowed: "
                        + Long.toHexString(cursor.getHeader().getDifficultyTarget()) + " vs "
                        + Long.toHexString(next.getDifficultyTarget()));
            }
        }
    }

    @Override
    public int getProtocolVersionNum(final NetworkParameters.ProtocolVersion version) {
        switch (version) {
            case PONG:
            case BLOOM_FILTER:
                return ONIXCOIN_PROTOCOL_VERSION_CURRENT;
            case CURRENT:
                return ONIXCOIN_PROTOCOL_VERSION_CURRENT;
            case MINIMUM:
            default:
                return ONIXCOIN_PROTOCOL_VERSION_CURRENT;
        }
    }

    @Override
    public boolean allowMoreInventoryTypes() {
        return true;
    }

    @Override
    public boolean allowMoreMessages() {
        return true;
    }

    @Override
    public AltcoinSerializer getSerializer(boolean parseRetain) {
        return new AltcoinSerializer(this, parseRetain);
    }

    @Override
    public String getTrustPeer() {
        return "107.170.213.97"; // 192.168.0.162
}
}
