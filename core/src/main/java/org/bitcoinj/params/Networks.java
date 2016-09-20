/*
 * Copyright 2014 Giannis Dzegoutanis
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

package org.bitcoinj.params;

import org.bitcoinj.core.NetworkParameters;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import java.util.Collection;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility class that holds all the registered NetworkParameters types used for Address auto discovery.
 * By default only MainNetParams and TestNet3Params are used. If you want to use TestNet2, RegTestParams or
 * UnitTestParams use the register and unregister the TestNet3Params as they don't have their own address
 * version/type code.
 */
public class Networks {
    public enum Family {
        BITCOIN,
        REDDCOIN,
        PEERCOIN,
        NUBITS,
        VPNCOIN,
        CLAMS,
        SOLARCOIN,
        GRIDCOIN
    }

    private static final Pattern bitcoinFamily = Pattern.compile(".*(bitcoin).*");
    private static final Pattern reddcoinFamily = Pattern.compile(".*(reddcoin).*");
    private static final Pattern peercoinFamily = Pattern.compile(".*(peercoin).*");
    private static final Pattern nubitsFamily = Pattern.compile(".*(nubits).*");
    private static final Pattern vpncoinFamily = Pattern.compile(".*(vpncoin).*");
    private static final Pattern clamsFamily = Pattern.compile(".*(clams).*");
    private static final Pattern solarcoinFamily = Pattern.compile(".*(solarcoin).*");
    private static final Pattern gridcoinFamily = Pattern.compile(".*(gridcoin).*");

    /** Registered networks */
    private static Set<NetworkParameters> networks = ImmutableSet.of(TestNet3Params.get(), MainNetParams.get());

    public static Set<NetworkParameters> get() {
        return networks;
    }

    public static void register(NetworkParameters network) {
        register(Lists.newArrayList(network));
    }

    public static void register(Collection<? extends NetworkParameters> networks) {
        ImmutableSet.Builder<NetworkParameters> builder = ImmutableSet.builder();
        builder.addAll(Networks.networks);
        builder.addAll(networks);
        Networks.networks = builder.build();
    }

    public static void unregister(NetworkParameters network) {
        if (networks.contains(network)) {
            ImmutableSet.Builder<NetworkParameters> builder = ImmutableSet.builder();
            for (NetworkParameters parameters : networks) {
                if (parameters.equals(network))
                    continue;
                builder.add(parameters);
            }
            networks = builder.build();
        }
    }

    public static boolean isFamily(NetworkParameters network, Family... family) {
        Family networkFamily = getFamily(network);
        for (Family f : family) {
            if (networkFamily == f) return true;
        }
        return false;
    }

    public static Family getFamily(NetworkParameters network) {
        if (network == null || network.getFamily() == null) {
            return Family.BITCOIN; // default is Bitcoin
        }

        if (bitcoinFamily.matcher(network.getFamilyString()).matches()) {
            return Family.BITCOIN;
        } else if (peercoinFamily.matcher(network.getFamilyString()).matches()) {
            return Family.PEERCOIN;
        } else if (nubitsFamily.matcher(network.getFamilyString()).matches()) {
            return Family.NUBITS;
        } else if (reddcoinFamily.matcher(network.getFamilyString()).matches()) {
            return Family.REDDCOIN;
        } else if (vpncoinFamily.matcher(network.getFamilyString()).matches()) {
            return Family.VPNCOIN;
        } else if (clamsFamily.matcher(network.getFamilyString()).matches()) {
            return Family.CLAMS;
        } else if (gridcoinFamily.matcher(network.getFamilyString()).matches()) {
            return Family.GRIDCOIN;
        } else if (solarcoinFamily.matcher(network.getFamilyString()).matches()) {
            return Family.SOLARCOIN;
        } else {
            return Family.BITCOIN; // everything else is Bitcoin
        }
    }
}
