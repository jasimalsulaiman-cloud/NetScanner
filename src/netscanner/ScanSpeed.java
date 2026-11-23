package netscanner;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The two scan modes offered to the user and the Nmap options behind each one.
 */
public enum ScanSpeed {

    /** Normal timing, the 1000 most common ports. Slower but more complete. */
    SLOW("Slow (detailed)", "-T3"),

    /** Aggressive timing, only the 100 most common ports. */
    FAST("Fast", "-T4", "-F");

    private final String label;
    private final List<String> nmapArgs;

    ScanSpeed(String label, String... nmapArgs) {
        this.label = label;
        this.nmapArgs = Collections.unmodifiableList(Arrays.asList(nmapArgs));
    }

    public List<String> getNmapArgs() {
        return nmapArgs;
    }

    @Override
    public String toString() {
        return label;
    }
}
