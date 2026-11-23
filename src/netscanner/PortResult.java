package netscanner;

/**
 * One open port found on a host.
 */
public class PortResult {

    private final int port;
    private final String protocol;
    private final String state;
    private final String service;
    private final String version;

    public PortResult(int port, String protocol, String state, String service, String version) {
        this.port = port;
        this.protocol = protocol;
        this.state = state;
        this.service = service;
        this.version = version;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getState() {
        return state;
    }

    public String getService() {
        return service;
    }

    public String getVersion() {
        return version;
    }
}
