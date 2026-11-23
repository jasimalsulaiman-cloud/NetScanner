package netscanner;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Turns scan results into a plain-text report that is saved (encrypted) to disk.
 */
public final class ReportBuilder {

    private ReportBuilder() {
    }

    public static String build(String target, ScanSpeed speed, Date started, long durationMs, List<HostResult> hosts) {
        StringBuilder sb = new StringBuilder();
        String line = repeat('=', 78);
        int openPorts = 0;
        for (HostResult h : hosts) {
            openPorts += h.getPorts().size();
        }

        sb.append(line).append('\n');
        sb.append("NetScanner - Network Scan Report\n");
        sb.append(line).append('\n');
        sb.append("Date        : ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(started)).append('\n');
        sb.append("Target      : ").append(target).append('\n');
        sb.append("Scan mode   : ").append(speed).append('\n');
        sb.append("Duration    : ").append(String.format("%.1f seconds", durationMs / 1000.0)).append('\n');
        sb.append("Hosts up    : ").append(hosts.size()).append('\n');
        sb.append("Open ports  : ").append(openPorts).append('\n');
        sb.append(line).append("\n\n");

        for (HostResult h : hosts) {
            sb.append("Host ").append(h.getIp());
            if (!h.getHostname().isEmpty()) {
                sb.append("  (").append(h.getHostname()).append(')');
            }
            sb.append('\n');
            if (!h.getMac().isEmpty()) {
                sb.append("  MAC: ").append(h.getMac());
                if (!h.getVendor().isEmpty()) {
                    sb.append("  [").append(h.getVendor()).append(']');
                }
                sb.append('\n');
            }
            if (h.getPorts().isEmpty()) {
                sb.append("  No open ports found.\n\n");
                continue;
            }
            sb.append(String.format("  %-10s %-10s %-16s %s%n", "PORT", "STATE", "SERVICE", "VERSION"));
            for (PortResult p : h.getPorts()) {
                sb.append(String.format("  %-10s %-10s %-16s %s%n",
                        p.getPort() + "/" + p.getProtocol(), p.getState(), p.getService(), p.getVersion()));
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private static String repeat(char c, int n) {
        char[] chars = new char[n];
        java.util.Arrays.fill(chars, c);
        return new String(chars);
    }
}
