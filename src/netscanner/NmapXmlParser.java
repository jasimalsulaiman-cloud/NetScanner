package netscanner;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Reads the XML report written by "nmap -oX" and turns it into Java objects.
 */
public final class NmapXmlParser {

    private NmapXmlParser() {
    }

    public static List<HostResult> parse(File xmlFile) throws IOException, SAXException, ParserConfigurationException {
        Document doc = newSafeBuilder().parse(xmlFile);
        List<HostResult> hosts = new ArrayList<HostResult>();

        NodeList hostNodes = doc.getElementsByTagName("host");
        for (int i = 0; i < hostNodes.getLength(); i++) {
            Element hostEl = (Element) hostNodes.item(i);

            Element status = firstChild(hostEl, "status");
            if (status == null || !"up".equals(status.getAttribute("state"))) {
                continue;
            }

            String ip = null;
            String mac = "";
            String vendor = "";
            NodeList addresses = hostEl.getElementsByTagName("address");
            for (int a = 0; a < addresses.getLength(); a++) {
                Element addr = (Element) addresses.item(a);
                String type = addr.getAttribute("addrtype");
                if ("ipv4".equals(type) || ("ipv6".equals(type) && ip == null)) {
                    ip = addr.getAttribute("addr");
                } else if ("mac".equals(type)) {
                    mac = addr.getAttribute("addr");
                    vendor = addr.getAttribute("vendor");
                }
            }
            if (ip == null) {
                continue;
            }

            HostResult host = new HostResult(ip);
            host.setMac(mac);
            host.setVendor(vendor);

            NodeList names = hostEl.getElementsByTagName("hostname");
            if (names.getLength() > 0) {
                host.setHostname(((Element) names.item(0)).getAttribute("name"));
            }

            NodeList portNodes = hostEl.getElementsByTagName("port");
            for (int p = 0; p < portNodes.getLength(); p++) {
                Element portEl = (Element) portNodes.item(p);
                Element stateEl = firstChild(portEl, "state");
                String state = stateEl == null ? "" : stateEl.getAttribute("state");
                if (!state.startsWith("open")) {
                    continue;
                }
                String service = "";
                String version = "";
                Element svc = firstChild(portEl, "service");
                if (svc != null) {
                    service = svc.getAttribute("name");
                    version = (svc.getAttribute("product") + " " + svc.getAttribute("version") + " "
                            + svc.getAttribute("extrainfo")).trim().replaceAll("\\s+", " ");
                }
                int portNumber;
                try {
                    portNumber = Integer.parseInt(portEl.getAttribute("portid"));
                } catch (NumberFormatException e) {
                    continue;
                }
                host.addPort(new PortResult(portNumber, portEl.getAttribute("protocol"), state, service, version));
            }
            hosts.add(host);
        }
        return hosts;
    }

    /** XML parser with external entities switched off (protects against XXE). */
    private static DocumentBuilder newSafeBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setExpandEntityReferences(false);
        f.setXIncludeAware(false);
        return f.newDocumentBuilder();
    }

    private static Element firstChild(Element parent, String tag) {
        NodeList list = parent.getElementsByTagName(tag);
        return list.getLength() == 0 ? null : (Element) list.item(0);
    }
}
