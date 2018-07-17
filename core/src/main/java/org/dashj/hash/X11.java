package org.dashj.hash;

import fr.cryptohash.*;

/**
 * Created by Hash Engineering on 4/24/14 for the X11 algorithm
 */
public class X11 {

    static BLAKE512 blake512 = new BLAKE512();
    static BMW512 bmw512= new BMW512();
    static Groestl512 groestl512 = new Groestl512();
    static Skein512 skein512 = new Skein512();
    static JH512 jh512 = new JH512();
    static Keccak512 keccak512 = new Keccak512();
    static Luffa512 luffa512 = new Luffa512();
    static CubeHash512 cubehash512 = new CubeHash512();
    static SHAvite512 shavite512 = new SHAvite512();
    static SIMD512 simd512 = new SIMD512();
    static ECHO512 echo512 = new ECHO512();

    public static byte[] digest(byte[] input, int offset, int length)
    {
         return x11(input, offset, length);
    }

    public static byte[] digest(byte[] input) {
         return x11(input, 0, input.length);
    }

    static native byte [] x11_native(byte [] input, int offset, int length);


    static byte [] x11(byte input[], int offset, int length)
    {
        byte [][] hash = new byte [11][];

        //Run the chain of algorithms
        blake512.update(input, offset, length);

        hash[0] = blake512.digest();

        hash[1] = bmw512.digest(hash[0]);

        hash[2] = groestl512.digest(hash[1]);

        hash[3] = skein512.digest(hash[2]);

        hash[4] = jh512.digest(hash[3]);

        hash[5] = keccak512.digest(hash[4]);

        hash[6] = luffa512.digest(hash[5]);

        hash[7] = cubehash512.digest(hash[6]);

        hash[8] = shavite512.digest(hash[7]);

        hash[9] = simd512.digest(hash[8]);

        hash[10] = echo512.digest(hash[9]);

        byte [] result = new byte[32];

        System.arraycopy(hash[10], 0, result, 0, result.length);

        return result;
    }
}
