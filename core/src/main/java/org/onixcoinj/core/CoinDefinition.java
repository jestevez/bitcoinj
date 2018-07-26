package org.onixcoinj.core;

import java.math.BigInteger;
import java.util.Map;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Sha256Hash;

/**
 * Created with IntelliJ IDEA. User: Hash Engineering Solutions Date: 5/3/14 To
 * change this template use File | Settings | File Templates.
 */
public class CoinDefinition {

    public static final String coinName = "Onix";
    public static final String coinTicker = "ONX";
    public static final String coinURIScheme = "onix";
    public static final String cryptsyMarketId = "155";
    public static final String cryptsyMarketCurrency = "BTC";
    public static final String PATTERN_PRIVATE_KEY_START_UNCOMPRESSED = "[7]";
    public static final String PATTERN_PRIVATE_KEY_START_COMPRESSED = "[X]";

    public enum CoinPrecision {
        Coins,
        Millicoins,
    }
    public static final CoinPrecision coinPrecision = CoinPrecision.Coins;

    public static final String UNSPENT_API_URL = "https://www.onixcoin.info/api/addr/ADDRESS/utxo?noCache=1";

    public enum UnspentAPIType {
        BitEasy,
        Blockr,
        Abe,
        Cryptoid,
    };
    public static final UnspentAPIType UnspentAPI = UnspentAPIType.Cryptoid;

    public static final String BLOCKEXPLORER_BASE_URL_PROD = "https://www.onixcoin.info/";  
    public static final String BLOCKEXPLORER_ADDRESS_PATH = "address/";             
    public static final String BLOCKEXPLORER_TRANSACTION_PATH = "tx/";              
    public static final String BLOCKEXPLORER_BLOCK_PATH = "block/";                 
    public static final String BLOCKEXPLORER_BASE_URL_TEST = "https://testnet.onixcoin.info/";

    public static final String DONATION_ADDRESS = "XTo7XEAgPapkgJkgH6iR31J4cHBxwTgREe";  //onixcoin.info donation DASH address

    enum CoinHash {
        SHA256,
        scrypt,
        x11
    };
    public static final CoinHash coinPOWHash = CoinHash.x11;

    public static boolean checkpointFileSupport = true;

    public static final int TARGET_TIMESPAN = (int) (60 * 60);  // 24 hours per difficulty cycle, on average.
    public static final int TARGET_SPACING = (int) (2.5 * 60);  // 2.5 minutes seconds per block.
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;  //57 blocks

    public static final int getInterval(int height, boolean testNet) {
        return INTERVAL;      //108
    }

    public static final int getIntervalCheckpoints() {
        return INTERVAL;

    }

    public static final int getTargetTimespan(int height, boolean testNet) {
        return TARGET_TIMESPAN;    //72 min
    }

    public static int COIN = 100000000;
    public static int spendableCoinbaseDepth = 100; //main.h: static const int COINBASE_MATURITY
    public static final long MAX_COINS = 1151200000 * COIN;  //    MAX_MONEY = 1151200000 * COIN;             //main.h:  MAX_MONEY

    public static final long DEFAULT_MIN_TX_FEE = 10000;   // MIN_TX_FEE
    public static final long DUST_LIMIT = 5460; //Transaction.h CTransaction::GetDustThreshold for 10000 MIN_TX_FEE
    public static final long INSTANTX_FEE = 100000; //0.001 DASH (updated for 12.1)
    public static final boolean feeCanBeRaised = false;

    //
    // Dash 0.12.1.x
    //
    public static final int PROTOCOL_VERSION = 70010;          //version.h PROTOCOL_VERSION
    public static final int MIN_PROTOCOL_VERSION = 70010;        //version.h MIN_PEER_PROTO_VERSION

    public static final int BLOCK_CURRENTVERSION = 1;   // main.h  CURRENT_VERSION
    public static final int MAX_BLOCK_SIZE = 4000000; // main.h  MAX_BLOCK_SIZE = 4000000;                      // 1000KB block hard limit

    public static final boolean supportsBloomFiltering = true; //Requires PROTOCOL_VERSION 70000 in the client

    public static final int Port = 41016;       //protocol.h GetDefaultPort(testnet=false)
    public static final int TestPort = 141016;     //protocol.h GetDefaultPort(testnet=true)

    //
    //  Production
    //
    public static final int AddressHeader = 75;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS
    public static final int p2shHeader = 5;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS
    public static final int dumpedPrivateKeyHeader = 128;   //common to all coins
    //public static final long oldPacketMagic = 0xf3c3b9de;      
    public static final long PacketMagic = 0xf3c3b9de; // https://github.com/jestevez/onixcore/blob/3d308b7c2f040f3347f09d0f6eedf4c6847b037c/networks.js#L9

    //Genesis Block Information from main.cpp: LoadBlockIndex
    static public long genesisBlockDifficultyTarget = (0x1e0ffff0L);         //main.cpp: LoadBlockIndex
    static public long genesisBlockTime = 1390095618L;                       //main.cpp: LoadBlockIndex
    static public long genesisBlockNonce = (28917698);                         //main.cpp: LoadBlockIndex
    static public String genesisHash = "000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43"; //main.cpp: hashGenesisBlock
    static public String genesisMerkleRoot = "64e1822ed56cd7068d031fb3a4758e79c19e3386c654066ee0a16791ab807bea";
    static public int genesisBlockValue = 50;                                                              //main.cpp: LoadBlockIndex
    //taken from the raw data of the block explorer
    static public String genesisTxInBytes = "000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43"; 
    static public String genesisTxOutBytes = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";

    //net.cpp strDNSSeed
    static public String[] dnsSeeds = new String[]{
        "seed5.cryptolife.net",
        "seed2.cryptolife.net",
        "seed3.cryptolife.net",
        "electrum6.cryptolife.net",
        "seed.onixcoin.info",
        "192.157.59.230" // running local node 
    };

    public static int minBroadcastConnections = 0;   //0 for default; Using 3 like BreadWallet.

    //
    // TestNet - Onix
    //
    
    // Testnet Genesis block:
    // CBlock(hash=000008da0e16960d6c2548da4831323b956d61370e2a3fdc5150188c5c478c49, input=0100000000000000000000000000000000000000000000000000000000000000000000002a5d09737c826a5f8c12307a9c71774cd2e752e2910c9618744f05bc929d01b07ac92153f0ff0f1eb86e964c, PoW=000008da0e16960d6c2548da4831323b956d61370e2a3fdc5150188c5c478c49, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=b0019d92bc054f7418960c91e252e7d24c77719c7a30128c5f6a827c73095d2a, nTime=1394723194, nBits=1e0ffff0, nNonce=1284927160, vtx=1)
    // CTransaction(hash=b0019d92bc054f7418960c91e252e7d24c77719c7a30128c5f6a827c73095d2a, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    // CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295), coinbase 04ffff001d0104474a6170616e546f6461792031332f4d61722f323031342057617973206579656420746f206d616b6520706c616e65732065617369657220746f2066696e6420696e206f6365616e)
    // CTxOut(nValue=400.00000000, scriptPubKey=040184710fa689ad5023690c80f3a4)
    // vMerkleTree: b0019d92bc054f7418960c91e252e7d24c77719c7a30128c5f6a827c73095d2a 
    public static final boolean supportsTestNet = true;
    public static final int testnetAddressHeader = 111;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS_TEST
    public static final int testnetp2shHeader = 196;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS_TEST
    public static final long testnetPacketMagic = 0xfec4bade;      //
    public static final String testnetGenesisHash = "000008da0e16960d6c2548da4831323b956d61370e2a3fdc5150188c5c478c49";
    static public long testnetGenesisBlockDifficultyTarget = (0x1e0ffff0L);         //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockTime = 1394723194L;                       //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockNonce = (1284927160L);                         //main.cpp: LoadBlockIndex

    //main.cpp GetBlockValue(height, fee)
    public static final Coin GetBlockReward(int height) {
        int COIN = 1;
        Coin nSubsidy = Coin.valueOf(100, 0);
        if (height == 1) {
            nSubsidy = Coin.valueOf(420000, 0);
        }
        return nSubsidy;
    }

    public static int subsidyDecreaseBlockCount = 60 * COIN;     //main.cpp GetBlockValue(height, fee)

    public static BigInteger proofOfWorkLimit = org.bitcoinj.core.Utils.decodeCompactBits(0x1e0fffffL);  //main.cpp bnProofOfWorkLimit (~uint256(0) >> 20); // digitalcoin: starting difficulty is 1 / 2^12
        //static CBigNum bnProofOfWorkLimit(~uint256(0) >> 20); // ONIX: starting difficulty is 1 / 2^12
        //static CBigNum bnInitialDifficulty(~uint256(0) >> 30);
    static public String[] testnetDnsSeeds = new String[]{
        "testnet-seed.onixcoin.io",
        "test.dnsseed.onixcoin.io",};
    //from main.h: CAlert::CheckSignature
    public static final String SATOSHI_KEY = "048240a8748a80a286b270ba126705ced4f2ce5a7847b3610ea3c06513150dade2a8512ed5ea86320824683fc0818f0ac019214973e677acd1244f6d0571fc5103";
    public static final String TESTNET_SATOSHI_KEY = "04517d8a699cb43d3938d7b24faaff7cda448ca4ea267723ba614784de661949bf632d6304316b244646dea079735b9a6fc4af804efb4752075b9fe2245e14e412";

    /**
     * The string returned by getId() for the main, production network where
     * people trade things.
     */
    public static final String ID_MAINNET = "org.onixcoin.production";
    /**
     * The string returned by getId() for the testnet.
     */
    public static final String ID_TESTNET = "org.onixcoin.test";
    /**
     * Unit test network.
     */
    public static final String ID_UNITTESTNET = "com.google.onixcoin.unittest";

    //checkpoints.cpp Checkpoints::mapCheckpoints
    public static void initCheckpoints(Map<Integer, Sha256Hash> checkpoints) {

        checkpoints.put(0,       Sha256Hash.wrap("000007140b7a6ca0b64965824f5731f6e86daadf19eb299033530b1e61236e43"));
        checkpoints.put(30000,   Sha256Hash.wrap("0000000000974475481a0c083a65d12806a58f94200e32860999450bf2049c2f"));
        checkpoints.put(60000,   Sha256Hash.wrap("0000000000123af5ae90c441ca59b3cc12fb5f49cd8cc734f7228ad1f6ef5c61"));
        checkpoints.put(90000,   Sha256Hash.wrap("000000000000179a0439dcd880f808685e8035206982dcacd09fc2f0e9235190"));
        checkpoints.put(120000,  Sha256Hash.wrap("000000000000020ab41d21692dfa81ca9b7dab22956212be9be02df36f3c8b49"));
    }

    //Unit Test Information
    public static final String UNITTEST_ADDRESS = "XgxQxd6B8iYgEEryemnJrpvoWZ3149MCkK";
    public static final String UNITTEST_ADDRESS_PRIVATE_KEY = "XDtvHyDHk4S3WJvwjxSANCpZiLLkKzoDnjrcRhca2iLQRtGEz1JZ";

}
