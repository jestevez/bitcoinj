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
 * @date 13-ene-2018
 *
 * @version 1.0.0
 * @author Jose Luis Estevez jose.estevez.prieto@gmail.com
 */
public class OnixcoinMainNetParams extends AbstractOnixcoinParams {
    private static final Logger log = LoggerFactory.getLogger(OnixcoinMainNetParams.class);
    protected final ReentrantLock lock = Threading.lock("blockchain");
    public static BigInteger proofOfWorkLimit = org.bitcoinj.core.Utils.decodeCompactBits(0x1e0fffffL);  //main.cpp
    
    /** Keeps a map of block hashes to StoredBlocks. */
    private final BlockStore blockStore;
    
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;
    
    public OnixcoinMainNetParams() {
        super();
        
        id = ID_ONIX_MAINNET;

        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L3105
        packetMagic = 0xf3c3b9de;
        maxTarget = Utils.decodeCompactBits(0x1e0fffffL);
        port = 41016;
        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/base58.h#L275
        addressHeader = 75; // PUBKEY_ADDRESS
        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/base58.h#L276
        p2shHeader = 5; // SCRIPT_ADDRESS
        acceptableAddressCodes = new int[]{addressHeader, p2shHeader};
        dumpedPrivateKeyHeader = 128;  //common to all coins

        
        genesisBlock = createGenesis(this);
        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L2795
        genesisBlock.setTime(1491940886L);
        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setNonce(1033603);
        
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 345600;

        String genesisHash = genesisBlock.getHashAsString();
        
        checkState(genesisHash.equals("000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43"));
        alertSigningKey = Hex.decode("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/net.cpp#L1195
        dnsSeeds = new String[]{
            "node.onixcoin.info",
            "seed.onixcoin.com",
            "electrum6.cryptolife.net"
        };
        
        //ypub
//        bip32HeaderPub = 0x049d7cb2;
//        bip32HeaderPriv = 0x049d7878;
        //xpub
        bip32HeaderPub = 0x0488b21e;
        bip32HeaderPriv = 0x0488ade4;

        checkpoints.put(0,       Sha256Hash.wrap("000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43"));
        checkpoints.put(30000,   Sha256Hash.wrap("0000000000974475481a0c083a65d12806a58f94200e32860999450bf2049c2f"));
        checkpoints.put(60000,   Sha256Hash.wrap("0000000000123af5ae90c441ca59b3cc12fb5f49cd8cc734f7228ad1f6ef5c61"));
        checkpoints.put(90000,   Sha256Hash.wrap("000000000000179a0439dcd880f808685e8035206982dcacd09fc2f0e9235190"));
        checkpoints.put(120000,  Sha256Hash.wrap("000000000000020ab41d21692dfa81ca9b7dab22956212be9be02df36f3c8b49"));

        checkpoints.put(269168,  Sha256Hash.wrap("000000000004edc83638eddda4c889a9c269b88b923ec7c70803cf38068ab393"));
        checkpoints.put(272069,  Sha256Hash.wrap("00000000000018df2e974823546c5373e8bdb078c2880049e4cfc3d8036ec665"));
        
        checkpoints.put(300000, Sha256Hash.wrap("00000000000502760fe120b5be6f315513af417cd7942ce4f760399d7fe37707"));
        checkpoints.put(301000, Sha256Hash.wrap("000000000004c7fbbb7ee14c8dccc5163f766a0828fe5111458ae083bc94ec15"));
        checkpoints.put(302000, Sha256Hash.wrap("00000000000352758df557025fe426025240e6e1379de176b2c75e3cfae3181f"));
        checkpoints.put(303000, Sha256Hash.wrap("0000000000058c5bed0aa9ab9c138593a508dbf8ff1d71f9089f081d559a8dc8"));
        checkpoints.put(304000, Sha256Hash.wrap("000000000001eb7863e9d3867dc947c55e1471024b56206d76ecbead5f09862e"));
        checkpoints.put(305000, Sha256Hash.wrap("00000000000295aa7b3c89eb9ebbb58b9b28133ad267bd0f3353ea7f7b8ac77c"));
        checkpoints.put(306000, Sha256Hash.wrap("00000000000073832dba9660b59beb1d05f36995dc8eefd94b997d37f29233fd"));
        checkpoints.put(307000, Sha256Hash.wrap("00000000000254f8d4f83dd173f9a8e9324d564d9fce5d569ee1e1a7d2eebda0"));
        checkpoints.put(308000, Sha256Hash.wrap("0000000000026c9f4750ef1c5c475919152186e672f5d65998009645353f1059"));
        checkpoints.put(309000, Sha256Hash.wrap("000000000002b37239c39992818251b862c8c8d1af403d5050d588e4eab9d0f6"));
        checkpoints.put(310000, Sha256Hash.wrap("000000000006423edd1f1c09de4b77d1fa1cb2082cff8972b045c3df285acab2"));
        checkpoints.put(311000, Sha256Hash.wrap("000000000005531ffe060f16f212179f73b5b810a32e979f921cdaa08e3a794f"));
        checkpoints.put(312000, Sha256Hash.wrap("00000000000461a40b2a7569279e12685a5b0d01a60684e0914f9b4a03048ceb"));
        checkpoints.put(313000, Sha256Hash.wrap("000000000001dbfcaf0c2cb23dc869f52163158c86b080580325c46d9901106d"));
        checkpoints.put(314000, Sha256Hash.wrap("00000000000003acb4c3f90932348a2ef627a27cfb48f28e9f7130f02004be07"));
        checkpoints.put(315000, Sha256Hash.wrap("000000000000434d1217ba061d6ef3e3a971680ae71cea0b9c42c65e64f9be69"));
        checkpoints.put(316000, Sha256Hash.wrap("000000000002a7a273852520aeb96b045f95b2fa15e235df9a2c915bb13c3662"));
        checkpoints.put(317000, Sha256Hash.wrap("000000000005a82db0ac7190e66d13089526d357ff067e8cef6449ea1b904ff0"));
        checkpoints.put(317500, Sha256Hash.wrap("0000000000033b345872b9749fddf57853f05a195c07689bb48a2b0fa72368bc"));
        checkpoints.put(317899, Sha256Hash.wrap("000000000003a185e15f9ebd7308bdda33fabc25e3f408dc6634dd787c4c3f8d"));
        // Block hito
        checkpoints.put(330000, Sha256Hash.wrap("000000000000447279ba6970cb91dcdaae693c1b4725cb4847fa05ce611256c6"));

        blockStore =  new MemoryBlockStore(this);
    }

    //ONIXCOIN Mainnet Genesis block:
    //CBlock(hash=000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43, input=010000000000000000000000000000000000000000000000000000000000000000000000ea7b80ab9167a1e06e0654c686339ec1798e75a4b31f038d06d76cd52e82e1641636ed58f0ff0f1e83c50f00, PoW=000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=64e1822ed56cd7068d031fb3a4758e79c19e3386c654066ee0a16791ab807bea, nTime=1491940886, nBits=1e0ffff0, nNonce=1033603, vtx=1)
    //CTransaction(hash=64e1822ed56cd7068d031fb3a4758e79c19e3386c654066ee0a16791ab807bea, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295), coinbase 04ffff001d0104126f6e69782067656e6573697320626c6f636b)
    //CTxOut(nValue=1.00000000, scriptPubKey=04678afdb0fe5548271967f1a67130)
    //vMerkleTree: 64e1822ed56cd7068d031fb3a4758e79c19e3386c654066ee0a16791ab807bea 
    
    private static AltcoinBlock createGenesis(AbstractOnixcoinParams params) {
        AltcoinBlock genesisBlock = new AltcoinBlock(params, Block.BLOCK_VERSION_GENESIS);
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
        genesisBlock.addTransaction(t);
        return genesisBlock;
    }

    private static OnixcoinMainNetParams instance;

    public static synchronized OnixcoinMainNetParams get() {
        if (instance == null) {
            instance = new OnixcoinMainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return ID_ONIX_MAINNET;
    }

    @Override
    public boolean isTestNet() {
        return false;
    }

    @Override
    public boolean allowMinDifficultyBlocks() {
        return false;
    }

    @Override
    public void checkDifficultyTransitions(StoredBlock sb, Block block, BlockStore bs) throws VerificationException, BlockStoreException {
         checkDifficultyTransitions(sb, block);
    }
    
    @Override
    public String[] getDnsSeeds() {
         return dnsSeeds;
    }
    
    
    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1168
    private void checkDifficultyTransitions(StoredBlock storedPrev, Block nextBlock) throws BlockStoreException, VerificationException {
        final long BlocksTargetSpacing	= 3 * 60;
        int TimeDaySeconds	= 60 * 60 * 24;
        long	PastSecondsMin	= (long) (TimeDaySeconds * 3 * 0.1); 
        long	PastSecondsMax	= (long) (TimeDaySeconds * 3 * 2.8);
        
        long	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
        long	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;
        
        // storedPrev.getHeight()+1
        PastSecondsMin = (long) (TimeDaySeconds * 0.01);
        PastSecondsMax = (long) (TimeDaySeconds * 0.14);       
        KimotoGravityWell(storedPrev, nextBlock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax, blockStore);
 
    }
     
    
    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1108
    private void KimotoGravityWell(StoredBlock storedPrev, Block nextBlock, long TargetBlocksSpacingSeconds, long PastBlocksMin, long PastBlocksMax,BlockStore blockStore)  throws BlockStoreException, VerificationException {
	/* current difficulty formula, megacoin - kimoto gravity well */
        //const CBlockIndex  *BlockLastSolved				= pindexLast;
        //const CBlockIndex  *BlockReading				= pindexLast;
        //const CBlockHeader *BlockCreating				= pblock;
        StoredBlock         BlockLastSolved             = storedPrev;
        StoredBlock         BlockReading                = storedPrev;
        Block               BlockCreating               = nextBlock;

        BlockCreating				= BlockCreating;
        long				PastBlocksMass				= 0;
        long				PastRateActualSeconds		= 0;
        long				PastRateTargetSeconds		= 0;
        double				PastRateAdjustmentRatio		= 1f;
        BigInteger			PastDifficultyAverage = BigInteger.valueOf(0);
        BigInteger			PastDifficultyAveragePrev = BigInteger.valueOf(0);;
        double				EventHorizonDeviation;
        double				EventHorizonDeviationFast;
        double				EventHorizonDeviationSlow;

        long start = System.currentTimeMillis();

        if (BlockLastSolved == null || BlockLastSolved.getHeight() == 0 || (long)BlockLastSolved.getHeight() < PastBlocksMin)
        { verifyDifficulty(proofOfWorkLimit, storedPrev, nextBlock); }

        int i = 0;
        long LatestBlockTime = BlockLastSolved.getHeader().getTimeSeconds();
        
        for (i = 1; BlockReading != null && BlockReading.getHeight() > 0; i++) {
            if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
            PastBlocksMass++;

            if (i == 1)	{ PastDifficultyAverage = BlockReading.getHeader().getDifficultyTargetAsInteger(); }
            else        { PastDifficultyAverage = ((BlockReading.getHeader().getDifficultyTargetAsInteger().subtract(PastDifficultyAveragePrev)).divide(BigInteger.valueOf(i)).add(PastDifficultyAveragePrev)); }
            PastDifficultyAveragePrev = PastDifficultyAverage;
            // FIX https://github.com/onix-project/onixcoin/commit/afa1242aaa73116b4d3fbd5de21462ea7ec3e196
            if (LatestBlockTime < BlockReading.getHeader().getTimeSeconds()) {
                if (BlockReading.getHeight() > 330000) { 
                    LatestBlockTime = BlockReading.getHeader().getTimeSeconds();
                }
            }
            PastRateActualSeconds			= LatestBlockTime - BlockReading.getHeader().getTimeSeconds();
            PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
            PastRateAdjustmentRatio			= 1.0f;
            
            if (BlockReading.getHeight() > 330000) {
                if (PastRateActualSeconds < 1) { PastRateActualSeconds = 1; }
            } else {
                if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
            }
            
            if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
                PastRateAdjustmentRatio			= (double)PastRateTargetSeconds / PastRateActualSeconds;
            }
            EventHorizonDeviation			= 1 + (0.7084 * java.lang.Math.pow((Double.valueOf(PastBlocksMass)/Double.valueOf(28.2)), -1.228));
            EventHorizonDeviationFast		= EventHorizonDeviation;
            EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;

            if (PastBlocksMass >= PastBlocksMin) {
                if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast))
                {
                    /*assert(BlockReading)*/;
                    break;
                }
            }
            StoredBlock BlockReadingPrev = blockStore.get(BlockReading.getHeader().getPrevBlockHash());
            if (BlockReadingPrev == null)
            {
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
    

    static double ConvertBitsToDouble(long nBits){
        long nShift = (nBits >> 24) & 0xff;

        double dDiff =
                (double)0x0000ffff / (double)(nBits & 0x00ffffff);

        while (nShift < 29)
        {
            dDiff *= 256.0;
            nShift++;
        }
        while (nShift > 29)
        {
            dDiff /= 256.0;
            nShift--;
        }

        return dDiff;
    }

    private void verifyDifficulty(BigInteger calcDiff, StoredBlock storedPrev, Block nextBlock)
    {
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
            if(height == 1) {
                 // FIXME Falta el calculo del Bloque 1 pre-minado!
            }
            ///if(System.getProperty("os.name").toLowerCase().contains("windows"))
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
            else
            {
                    if (calcDiff.compareTo(receivedDifficulty) != 0)
                        throw new VerificationException("[BLOCK "+height+"] Network provided difficulty bits do not match what was calculated: " +
                                receivedDifficulty.toString(16) + " vs " + calcDiff.toString(16));
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
            if (next.getDifficultyTargetAsInteger().equals(this.getMaxTarget()))
                return;
            else throw new VerificationException("Unexpected change in difficulty");
        }
        else {
            // Walk backwards until we find a block that doesn't have the easiest proof of work, then check
            // that difficulty is equal to that one.
            StoredBlock cursor = storedPrev;
            while (!cursor.getHeader().equals(this.getGenesisBlock()) &&
                   cursor.getHeight() % this.getInterval() != 0 &&
                   cursor.getHeader().getDifficultyTargetAsInteger().equals(this.getMaxTarget()))
                cursor = cursor.getPrev(blockStore);
            BigInteger cursorTarget = cursor.getHeader().getDifficultyTargetAsInteger();
            BigInteger newTarget = next.getDifficultyTargetAsInteger();
            if (!cursorTarget.equals(newTarget))
                throw new VerificationException("Testnet block transition that is not allowed: " +
                    Long.toHexString(cursor.getHeader().getDifficultyTarget()) + " vs " +
                    Long.toHexString(next.getDifficultyTarget()));
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
    public boolean allowMoreInventoryTypes() { return true; }

    @Override
    public boolean allowMoreMessages() { return true; }
    
    @Override
    public AltcoinSerializer getSerializer(boolean parseRetain) {
        return new AltcoinSerializer(this, parseRetain);
    }
    
    @Override
    public String getTrustPeer() {
        return "node.onixcoin.info";
    }
}
