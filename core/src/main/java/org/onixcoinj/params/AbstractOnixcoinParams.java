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

import java.math.BigInteger;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Coin;
import static org.bitcoinj.core.Coin.COIN;
import org.bitcoinj.core.NetworkParameters;
import static org.bitcoinj.core.NetworkParameters.TARGET_SPACING;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.MonetaryFormat;
import org.dashj.hash.X11;
import org.libdohj.core.AltcoinNetworkParameters;
import org.libdohj.core.AltcoinSerializer;
import static org.onixcoinj.params.OnixcoinMainNetParams.proofOfWorkLimit;
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
    
    
    /** Keeps a map of block hashes to StoredBlocks. */
    private final BlockStore blockStore;
    
    
    private boolean powAllowMinimumDifficulty = true;
    private int fixKGWHeight = 330000;
    private int powDGWHeight = 345600;
    private int powDGWHeightTestNet = 20500;
    

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
    public static final String ID_ONIX_REGTEST = "info.onixcoin.regtest";

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = ID_ONIX_MAINNET ;
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = ID_ONIX_TESTNET ;
    /** The string returned by getId() for regtest mode. */
    public static final String ID_REGTEST = ID_ONIX_REGTEST;
    /** Unit test network. */
    public static final String ID_UNITTESTNET = "info.onixcoin.unittest";


    public static final int ONIXCOIN_PROTOCOL_VERSION_MINIMUM = 70012;
    public static final int ONIXCOIN_PROTOCOL_VERSION_CURRENT = 70012;

    // https://github.com/jestevez/onixcoin/blob/28aec388d7014fcc2bf1de60f2113b85d1840ddf/src/main.cpp#L1068
    private static final Coin BASE_SUBSIDY = COIN.multiply(60);
    private static final Coin PREMINE = COIN.multiply(100000000);
    private static final Coin GENESIS = COIN.multiply(0);

    protected Logger log = LoggerFactory.getLogger(AbstractOnixcoinParams.class);

    public AbstractOnixcoinParams() {
        super();
        interval = ONIX_INTERVAL;
        targetTimespan = ONIX_TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1e0fffffL); // TODO: figure out the Onixcoin value of this

        blockStore =  new MemoryBlockStore(this);
    }
    

    @Override
    public Coin getBlockSubsidy(final int height) {
        
        
        if (height == 0) {
            return GENESIS;// genesis
        }

        if (height == 1) {
            return PREMINE;// pre-mine
        }
        
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
    
    // https://github.com/onix-project/onixcoin/blob/1393fcf238823518bc9c20e6739d8a275507590f/src/main.cpp#L1281
    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
                                           final BlockStore blockStore) throws VerificationException, BlockStoreException {
        int height = storedPrev.getHeight() + 1;
        int DiffMode = 1;
        
        if(NetworkParameters.ID_TESTNET.equals(this.getId())) {
            if(height >= powDGWHeightTestNet) {
                DiffMode = 2; 
            }
            else {
                DiffMode = 1; 
            }
        }
        else {
            if(height >= powDGWHeight) {
                DiffMode = 2;
            } else {
                DiffMode = 1; 
            }
        }
        
        if(DiffMode == 1) {
            checkDifficultyTransitions(storedPrev, nextBlock);
        }
        else {
            DarkGravityWave3(storedPrev, nextBlock, blockStore);
        }
        
    }
    
    
    // https://github.com/onix-project/onixcoin/blob/1393fcf238823518bc9c20e6739d8a275507590f/src/main.cpp#L1266
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
    
    // https://github.com/onix-project/onixcoin/blob/1393fcf238823518bc9c20e6739d8a275507590f/src/main.cpp#L1185
    protected void DarkGravityWave3(final StoredBlock storedPrev, final Block nextBlock,
                                  final BlockStore blockStore) {
        /* current difficulty formula, darkcoin - DarkGravity v3, written by Evan Duffield - evan@darkcoin.io */
        StoredBlock BlockLastSolved = storedPrev;
        StoredBlock BlockReading = storedPrev;
        Block BlockCreating = nextBlock;
        BlockCreating = BlockCreating;
        long nActualTimespan = 0;
        long LastBlockTime = 0;
        long PastBlocksMin = 24;
        long PastBlocksMax = 24;
        long CountBlocks = 0;
        BigInteger PastDifficultyAverage = BigInteger.ZERO;
        BigInteger PastDifficultyAveragePrev = BigInteger.ZERO;

        if (BlockLastSolved == null || BlockLastSolved.getHeight() == 0 || BlockLastSolved.getHeight() < PastBlocksMin) {
            // This is the first block or the height is < PastBlocksMin
            // Return minimal required work. (1e0fffff)
            verifyDifficulty(this.getMaxTarget(), storedPrev, nextBlock);
            return;
        }

         // loop over the past n blocks, where n == PastBlocksMax
        for (int i = 1; BlockReading != null && BlockReading.getHeight() > 0; i++) {
            if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
            CountBlocks++;

            if(CountBlocks <= PastBlocksMin) {
                if (CountBlocks == 1) { PastDifficultyAverage = BlockReading.getHeader().getDifficultyTargetAsInteger(); }
                else { PastDifficultyAverage = ((PastDifficultyAveragePrev.multiply(BigInteger.valueOf(CountBlocks)).add(BlockReading.getHeader().getDifficultyTargetAsInteger()).divide(BigInteger.valueOf(CountBlocks + 1)))); }
                PastDifficultyAveragePrev = PastDifficultyAverage;
            }

            // If this is the second iteration (LastBlockTime was set)
            if(LastBlockTime > 0){
                // Calculate time difference between previous block and current block
                long Diff = (LastBlockTime - BlockReading.getHeader().getTimeSeconds());
                // Increment the actual timespan
                nActualTimespan += Diff;
            }
            
            // Set LasBlockTime to the block time for the block in current iteration
            LastBlockTime = BlockReading.getHeader().getTimeSeconds();

            try {
                StoredBlock BlockReadingPrev = blockStore.get(BlockReading.getHeader().getPrevBlockHash());
                if (BlockReadingPrev == null)
                {
                    //assert(BlockReading); break;
                    return;
                }
                BlockReading = BlockReadingPrev;
            }
            catch(BlockStoreException x)
            {
                return;
            }
        }

        // bnNew is the difficulty
        BigInteger bnNew= PastDifficultyAverage;
        
        long nTargetTimespan = CountBlocks* ONIX_TARGET_SPACING;//nTargetSpacing;
        // Limit the re-adjustment to 3x or 0.33x
        // We don't want to increase/decrease diff too much.
        if (nActualTimespan < nTargetTimespan/3)
            nActualTimespan = nTargetTimespan/3;
        if (nActualTimespan > nTargetTimespan*3)
            nActualTimespan = nTargetTimespan*3;

        // Calculate the new difficulty based on actual and target timespan.
        // Retarget
        bnNew = bnNew.multiply(BigInteger.valueOf(nActualTimespan));
        bnNew = bnNew.divide(BigInteger.valueOf(nTargetTimespan));
        
        // If calculated difficulty is lower than the minimal diff, set the new difficulty to be the minimal diff.
        if (bnNew.compareTo(proofOfWorkLimit) > 0) {
            bnNew = proofOfWorkLimit;
        }
        
        verifyDifficulty(bnNew, storedPrev, nextBlock);

    }
    
    //  @HashEngineering
    public void DarkGravityWave(StoredBlock storedPrev, Block nextBlock,
                                  final BlockStore blockStore) throws VerificationException {
        /* current difficulty formula, darkcoin - DarkGravity v3, written by Evan Duffield - evan@darkcoin.io */
        long pastBlocks = 24;

        if (storedPrev == null || storedPrev.getHeight() == 0 || storedPrev.getHeight() < pastBlocks) {
            verifyDifficulty(storedPrev, nextBlock, getMaxTarget());
            return;
        }

//        if(powAllowMinimumDifficulty)
//        {
//            // recent block is more than 2 hours old
//            if (nextBlock.getTimeSeconds() > storedPrev.getHeader().getTimeSeconds() + 2 * 60 * 60) {
//                verifyDifficulty(storedPrev, nextBlock, getMaxTarget());
//                return;
//            }
//            // recent block is more than 10 minutes old
//            if (nextBlock.getTimeSeconds() > storedPrev.getHeader().getTimeSeconds() + NetworkParameters.TARGET_SPACING*4) {
//                BigInteger newTarget = storedPrev.getHeader().getDifficultyTargetAsInteger().multiply(BigInteger.valueOf(10));
//                verifyDifficulty(storedPrev, nextBlock, newTarget);
//                return;
//            }
//        }
        
        StoredBlock cursor = storedPrev;
        BigInteger pastTargetAverage = BigInteger.ZERO;
        for(int countBlocks = 1; countBlocks <= pastBlocks; countBlocks++) {
            BigInteger target = cursor.getHeader().getDifficultyTargetAsInteger();
            if(countBlocks == 1) {
                pastTargetAverage = target;
            } else {
                pastTargetAverage = pastTargetAverage.multiply(BigInteger.valueOf(countBlocks)).add(target).divide(BigInteger.valueOf(countBlocks+1));
            }
            if(countBlocks != pastBlocks) {
                try {
                    cursor = cursor.getPrev(blockStore);
                    if(cursor == null) {
                        //when using checkpoints, the previous block will not exist until 24 blocks are in the store.
                        return;
                    }
                } catch (BlockStoreException x) {
                    //when using checkpoints, the previous block will not exist until 24 blocks are in the store.
                    return;
                }
            }
        }


        BigInteger newTarget = pastTargetAverage;

        long timespan = storedPrev.getHeader().getTimeSeconds() - cursor.getHeader().getTimeSeconds();
        long targetTimespan = pastBlocks*TARGET_SPACING;

        if (timespan < targetTimespan/3)
            timespan = targetTimespan/3;
        if (timespan > targetTimespan*3)
            timespan = targetTimespan*3;

        // Retarget
        newTarget = newTarget.multiply(BigInteger.valueOf(timespan));
        newTarget = newTarget.divide(BigInteger.valueOf(targetTimespan));
        verifyDifficulty(storedPrev, nextBlock, newTarget);

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
                if (BlockReading.getHeight() > fixKGWHeight) { 
                    LatestBlockTime = BlockReading.getHeader().getTimeSeconds();
                }
            }
            PastRateActualSeconds			= LatestBlockTime - BlockReading.getHeader().getTimeSeconds();
            PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
            PastRateAdjustmentRatio			= 1.0f;
            
            if (BlockReading.getHeight() > fixKGWHeight) {
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
    
    protected long calculateNextDifficulty(StoredBlock storedBlock, Block nextBlock, BigInteger newTarget) {
        if (newTarget.compareTo(this.getMaxTarget()) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newTarget.toString(16));
            newTarget = this.getMaxTarget();
        }

        int accuracyBytes = (int) (nextBlock.getDifficultyTarget() >>> 24) - 3;

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newTarget = newTarget.and(mask);
        return Utils.encodeCompactBits(newTarget);
    }
    
    protected void verifyDifficulty(StoredBlock storedPrev, Block nextBlock, BigInteger newTarget) throws VerificationException {
        long newTargetCompact = calculateNextDifficulty(storedPrev, nextBlock, newTarget);
        long receivedTargetCompact = nextBlock.getDifficultyTarget();

        if (newTargetCompact != receivedTargetCompact)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    Long.toHexString(newTargetCompact) + " vs " + Long.toHexString(receivedTargetCompact));
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

        int height = storedPrev.getHeight() + 1;
        if(height == 1) {
             // FIXME Falta el calculo del Bloque 1 pre-minado!
        }
        else
        {
                if (calcDiff.compareTo(receivedDifficulty) != 0)
                    throw new VerificationException("[BLOCK "+height+"] Network provided difficulty bits do not match what was calculated: " +
                            receivedDifficulty.toString(16) + " vs " + calcDiff.toString(16));
        }

    }


    public abstract String getTrustPeer();

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_MAINNET)) {
            return org.onixcoinj.params.OnixcoinMainNetParams.get();
        } else if (id.equals(ID_TESTNET)) {
            return org.onixcoinj.params.OnixcoinTestNetParams.get();
        } else {
            return null;
        }
    }
}
