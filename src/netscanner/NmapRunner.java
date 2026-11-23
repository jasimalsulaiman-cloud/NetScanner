package netscanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Starts Nmap as a separate process, shows its live output, then parses the XML result.
 */
public class NmapRunner {

    /** Receives each line Nmap prints while it is running. */
    public interface LogListener {
        void onLine(String line);
    }

    /** Thrown when the scan cannot be run or is stopped. */
    public static class ScanException extends Exception {
        private static final long serialVersionUID = 1L;

        public ScanException(String message) {
            super(message);
        }

        public ScanException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Places Nmap is usually installed when it is not on the PATH. */
    private static final String[] NMAP_CANDIDATES = {
        "nmap",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe"
    };

    /** IPs, CIDR ranges (192.168.1.0/24), dash ranges (192.168.1.1-50) and host names. */
    private static final Pattern VALID_TARGET = Pattern.compile("[A-Za-z0-9][A-Za-z0-9.:/,\\-]*( [A-Za-z0-9][A-Za-z0-9.:/,\\-]*)*");

    private final String nmapPath;
    private volatile Process process;
    private volatile boolean cancelled;

    public NmapRunner(String nmapPath) {
        this.nmapPath = nmapPath;
    }

    /** Returns the Nmap command that works on this computer, or null if Nmap is not installed. */
    public static String findNmap() {
        for (String candidate : NMAP_CANDIDATES) {
            if (works(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    /** Returns the first line of "nmap --version", for display in the window. */
    public static String versionOf(String nmapPath) {
        try {
            Process p = new ProcessBuilder(nmapPath, "--version").redirectErrorStream(true).start();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), Charset.defaultCharset()));
            String line;
            String first = null;
            while ((line = r.readLine()) != null) {
                if (first == null && !line.trim().isEmpty()) {
                    first = line.trim();
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);
            return first == null ? "Nmap" : first;
        } catch (Exception e) {
            return "Nmap";
        }
    }

    private static boolean works(String command) {
        try {
            Process p = new ProcessBuilder(command, "--version").redirectErrorStream(true).start();
            p.getInputStream().close();
            if (!p.waitFor(10, TimeUnit.SECONDS)) {
                p.destroy();
                return false;
            }
            return p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public static boolean isValidTarget(String target) {
        return target != null && VALID_TARGET.matcher(target.trim()).matches();
    }

    /** Builds the full Nmap command line for a scan. */
    List<String> buildCommand(String target, ScanSpeed speed, File xmlOut) {
        List<String> cmd = new ArrayList<String>();
        cmd.add(nmapPath);
        cmd.add("-sV");            // detect service name and version on open ports
        cmd.add("-v");             // print open ports as they are found
        cmd.addAll(speed.getNmapArgs());
        cmd.add("-oX");            // machine-readable report for the parser
        cmd.add(xmlOut.getAbsolutePath());
        for (String part : target.trim().split("\\s+")) {
            cmd.add(part);
        }
        return cmd;
    }

    /**
     * Runs the scan and blocks until it finishes. Call from a background thread.
     */
    public List<HostResult> scan(String target, ScanSpeed speed, LogListener log) throws ScanException {
        if (!isValidTarget(target)) {
            throw new ScanException("Invalid target: " + target);
        }
        cancelled = false;
        File xml = null;
        try {
            xml = File.createTempFile("netscanner-", ".xml");
            List<String> cmd = buildCommand(target, speed, xml);
            log.onLine("$ " + String.join(" ", cmd));

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            process = pb.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), Charset.defaultCharset()));
            String line;
            while ((line = reader.readLine()) != null) {
                log.onLine(line);
            }
            int exit = process.waitFor();

            if (cancelled) {
                throw new ScanException("Scan stopped by the user.");
            }
            if (exit != 0) {
                throw new ScanException("Nmap finished with error code " + exit + ". See the log for details.");
            }
            return NmapXmlParser.parse(xml);
        } catch (ScanException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanException("Scan interrupted.", e);
        } catch (Exception e) {
            throw new ScanException("Scan failed: " + e.getMessage(), e);
        } finally {
            process = null;
            if (xml != null && !xml.delete()) {
                xml.deleteOnExit();
            }
        }
    }

    /** Stops a running scan. */
    public void cancel() {
        cancelled = true;
        Process p = process;
        if (p != null) {
            p.destroy();
        }
    }
}
