package netscanner;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Locale;

/**
 * Finds the computer's own IPv4 address and the subnet it is connected to.
 */
public final class NetworkDetector {

    /** Names of virtual adapters that should not be picked as the main network. */
    private static final String[] VIRTUAL_NAMES = {
        "docker", "vbox", "virtualbox", "vmnet", "vmware", "veth", "br-", "utun", "tun", "tap", "hyper-v", "vethernet"
    };

    private NetworkDetector() {
    }

    /** Result of the detection. */
    public static final class NetworkInfo {
        private final String interfaceName;
        private final String ip;
        private final int prefixLength;
        private final String suggestedTarget;

        NetworkInfo(String interfaceName, String ip, int prefixLength, String suggestedTarget) {
            this.interfaceName = interfaceName;
            this.ip = ip;
            this.prefixLength = prefixLength;
            this.suggestedTarget = suggestedTarget;
        }

        public String getInterfaceName() {
            return interfaceName;
        }

        public String getIp() {
            return ip;
        }

        public int getPrefixLength() {
            return prefixLength;
        }

        /** Subnet in CIDR form, for example 192.168.1.0/24. */
        public String getSuggestedTarget() {
            return suggestedTarget;
        }
    }

    /**
     * Returns the first active, non-loopback IPv4 address, preferring private LAN
     * addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x). Returns null if none is found.
     */
    public static NetworkInfo detect() throws SocketException {
        NetworkInfo fallback = null;
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!ni.isUp() || ni.isLoopback() || ni.isVirtual() || isVirtualName(ni)) {
                continue;
            }
            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                InetAddress address = ia.getAddress();
                if (!(address instanceof Inet4Address)) {
                    continue;
                }
                int prefix = ia.getNetworkPrefixLength();
                if (prefix <= 0 || prefix > 32) {
                    prefix = 24;
                }
                // Very large networks (/16, /8) would take hours to scan,
                // so the suggestion is narrowed to the computer's own /24.
                int suggestedPrefix = Math.max(prefix, 24);
                String target = networkAddress(address.getAddress(), suggestedPrefix) + "/" + suggestedPrefix;
                NetworkInfo info = new NetworkInfo(ni.getDisplayName(), address.getHostAddress(), prefix, target);
                if (address.isSiteLocalAddress()) {
                    return info;
                }
                if (fallback == null) {
                    fallback = info;
                }
            }
        }
        return fallback;
    }

    private static boolean isVirtualName(NetworkInterface ni) {
        String name = (ni.getName() + " " + ni.getDisplayName()).toLowerCase(Locale.ROOT);
        for (String v : VIRTUAL_NAMES) {
            if (name.contains(v)) {
                return true;
            }
        }
        return false;
    }

    /** Applies the subnet mask to an IPv4 address, e.g. 192.168.1.37 /24 gives 192.168.1.0 */
    static String networkAddress(byte[] ip, int prefix) {
        int addr = ((ip[0] & 0xFF) << 24) | ((ip[1] & 0xFF) << 16) | ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
        int mask = prefix == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - prefix));
        int net = addr & mask;
        return ((net >>> 24) & 0xFF) + "." + ((net >>> 16) & 0xFF) + "." + ((net >>> 8) & 0xFF) + "." + (net & 0xFF);
    }
}
