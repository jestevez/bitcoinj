/*
 * Copyright 2015 Ross Nicoll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.libdohj.core;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Sha256Hash;

/**
 *
 * @author Ross Nicoll
 */
public interface AltcoinNetworkParameters {
    /**
     * Get the hash for the given block, for comparing against target difficulty.
     * This provides an extension hook for networks which use a hash other than
     * SHA256 twice (Bitcoin standard) for proof of work.
     */
    Sha256Hash getBlockDifficultyHash(Block block);

    /**
     * Most coins use SHA256D for block hashes,
     * but some do not.  If a coin uses SHA256D, then isBlockHashSHA256D should
     * return true and calculateBlockHash should return null;
     */

    /**
     *
     * @return true if the coin uses SHA256D like bitcoin, false if it uses a different hash function
     */
    boolean isBlockHashSHA256D();

    /**
     *
     * @param input The byte array containing the block header
     * @param offset The offset to the starting position of the block header
     * @param length The length of the block header which should be 80 bytes.
     * @return The hash of the block header.  null if using the standard bitcoin hash function (SHA256D)
     */
    Sha256Hash calculateBlockHash(byte[] input, int offset, int length);

    public boolean isTestNet();

    /**
     * Get the subsidy (i.e. maximum number of coins that can be generated
     * by the coinbase transaction) for a block at the given height.
     */
    public Coin getBlockSubsidy(final int height);
}
