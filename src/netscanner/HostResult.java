package netscanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * One live host found by the scan, with its open ports.
 */
public class HostResult {

    private final String ip;
    private String hostname = "";
    private String mac = "";
    private String vendor = "";
    private final List<PortResult> ports = new ArrayList<PortResult>();

    public HostResult(String ip) {
        this.ip = ip;
    }

    public String getIp() {
        return ip;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname == null ? "" : hostname;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac == null ? "" : mac;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor == null ? "" : vendor;
    }

    public void addPort(PortResult port) {
        ports.add(port);
    }

    public List<PortResult> getPorts() {
        return Collections.unmodifiableList(ports);
    }
}
