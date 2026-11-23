package netscanner;

import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;

/**
 * Quick checks without a GUI: encryption round trip, XML parsing and a real scan of 127.0.0.1.
 * Run:  java -cp out netscanner.SelfTest
 */
public final class SelfTest {

    public static void main(String[] args) throws Exception {
        // 1. Encryption
        String text = "hello report";
        byte[] enc = ReportCrypto.encrypt(text, "secret123".toCharArray());
        check(ReportCrypto.decrypt(enc, "secret123".toCharArray()).equals(text), "decrypt with right password");
        try {
            ReportCrypto.decrypt(enc, "wrong".toCharArray());
            check(false, "wrong password rejected");
        } catch (GeneralSecurityException e) {
            check(true, "wrong password rejected");
        }

        // 2. Network detection
        NetworkDetector.NetworkInfo info = NetworkDetector.detect();
        System.out.println("Detected: " + (info == null ? "none" : info.getIp() + " -> " + info.getSuggestedTarget()));
        check("192.168.1.0".equals(NetworkDetector.networkAddress(new byte[]{(byte) 192, (byte) 168, 1, 37}, 24)), "network address");

        // 3. Target validation
        check(NmapRunner.isValidTarget("192.168.1.0/24"), "valid CIDR");
        check(!NmapRunner.isValidTarget("-oN /etc/passwd"), "option injection blocked");
        check(!NmapRunner.isValidTarget("1.1.1.1; rm -rf /"), "shell characters blocked");

        // 4. Real scan of this machine
        String nmap = NmapRunner.findNmap();
        if (nmap == null) {
            System.out.println("Nmap not installed - scan test skipped");
            return;
        }
        long t0 = System.currentTimeMillis();
        List<HostResult> hosts = new NmapRunner(nmap).scan("127.0.0.1", ScanSpeed.FAST, line -> { });
        check(!hosts.isEmpty(), "localhost found");
        System.out.println(ReportBuilder.build("127.0.0.1", ScanSpeed.FAST, new Date(t0),
                System.currentTimeMillis() - t0, hosts));
        System.out.println("ALL TESTS PASSED");
    }

    private static void check(boolean ok, String name) {
        System.out.println((ok ? "[OK]   " : "[FAIL] ") + name);
        if (!ok) {
            System.exit(1);
        }
    }

    private SelfTest() {
    }
}
