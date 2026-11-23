package netscanner;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

/**
 * Main application window: network info, scan options, results table, log and save buttons.
 */
public final class MainWindow extends JFrame {

    private static final long serialVersionUID = 1L;
    private static final String[] COLUMNS = {"IP address", "Host name", "Port", "Protocol", "State", "Service", "Version"};

    private final JLabel myIpLabel = new JLabel("-");
    private final JLabel interfaceLabel = new JLabel("-");
    private final JLabel nmapLabel = new JLabel("-");
    private final JTextField targetField = new JTextField(22);
    private final JRadioButton slowRadio = new JRadioButton(ScanSpeed.SLOW.toString());
    private final JRadioButton fastRadio = new JRadioButton(ScanSpeed.FAST.toString(), true);
    private final JButton detectButton = new JButton("Detect network");
    private final JButton scanButton = new JButton("Scan");
    private final JButton stopButton = new JButton("Stop");
    private final JButton saveButton = new JButton("Save encrypted report");
    private final JButton openButton = new JButton("Open encrypted report");
    private final JProgressBar progress = new JProgressBar();
    private final JLabel statusLabel = new JLabel("Ready.");
    private final JTextArea logArea = new JTextArea(10, 80);
    private final DefaultTableModel tableModel = new DefaultTableModel(COLUMNS, 0) {
        private static final long serialVersionUID = 1L;

        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    private String nmapPath;
    private transient NmapRunner runner;
    private String lastReport;

    public MainWindow() {
        super("NetScanner - Simple Network Scanner (Nmap)");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(900, 600));
        setLayout(new BorderLayout(8, 8));

        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
        add(buildBottomPanel(), BorderLayout.SOUTH);

        wireActions();
        pack();
        setSize(1050, 700);
        setLocationRelativeTo(null);

        detectNmap();
        detectNetwork();
    }

    // ------------------------------------------------------------------ layout

    private JPanel buildTopPanel() {
        JPanel info = new JPanel(new GridBagLayout());
        info.setBorder(BorderFactory.createTitledBorder("Your network"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 6, 3, 6);
        c.anchor = GridBagConstraints.WEST;

        c.gridx = 0; c.gridy = 0; info.add(new JLabel("Your IP:"), c);
        c.gridx = 1; info.add(bold(myIpLabel), c);
        c.gridx = 2; info.add(new JLabel("Interface:"), c);
        c.gridx = 3; info.add(interfaceLabel, c);
        c.gridx = 4; info.add(new JLabel("Nmap:"), c);
        c.gridx = 5; c.weightx = 1; info.add(nmapLabel, c);

        JPanel options = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        options.setBorder(BorderFactory.createTitledBorder("Scan"));
        options.add(new JLabel("Target (IP / subnet):"));
        options.add(targetField);
        options.add(detectButton);
        options.add(new JLabel("   Speed:"));
        ButtonGroup speedGroup = new ButtonGroup();
        speedGroup.add(slowRadio);
        speedGroup.add(fastRadio);
        options.add(slowRadio);
        options.add(fastRadio);
        options.add(scanButton);
        options.add(stopButton);
        stopButton.setEnabled(false);

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
        top.add(info, BorderLayout.NORTH);
        top.add(options, BorderLayout.SOUTH);
        return top;
    }

    private JSplitPane buildCenterPanel() {
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Results"));

        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Nmap log"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, logScroll);
        split.setResizeWeight(0.65);
        split.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        return split;
    }

    private JPanel buildBottomPanel() {
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        progress.setPreferredSize(new Dimension(160, 16));
        left.add(progress);
        left.add(statusLabel);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        saveButton.setEnabled(false);
        right.add(saveButton);
        right.add(openButton);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 8));
        bottom.add(left, BorderLayout.WEST);
        bottom.add(right, BorderLayout.EAST);
        return bottom;
    }

    private static JLabel bold(JLabel label) {
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        return label;
    }

    private void wireActions() {
        detectButton.addActionListener(e -> detectNetwork());
        scanButton.addActionListener(e -> startScan());
        targetField.addActionListener(e -> startScan());
        stopButton.addActionListener(e -> stopScan());
        saveButton.addActionListener(e -> saveEncrypted());
        openButton.addActionListener(e -> openEncrypted());
    }

    // ------------------------------------------------------------------ actions

    private void detectNmap() {
        nmapPath = NmapRunner.findNmap();
        if (nmapPath == null) {
            nmapLabel.setText("not found - install from nmap.org");
            scanButton.setEnabled(false);
            JOptionPane.showMessageDialog(this,
                    "Nmap was not found on this computer.\n\n"
                            + "Install it from https://nmap.org/download.html\n"
                            + "(Windows: run the installer, macOS: brew install nmap, Linux: sudo apt install nmap)\n"
                            + "then restart NetScanner.",
                    "Nmap not found", JOptionPane.WARNING_MESSAGE);
        } else {
            nmapLabel.setText(NmapRunner.versionOf(nmapPath));
        }
    }

    private void detectNetwork() {
        try {
            NetworkDetector.NetworkInfo info = NetworkDetector.detect();
            if (info == null) {
                myIpLabel.setText("no network");
                interfaceLabel.setText("-");
                targetField.setText("127.0.0.1");
                statusLabel.setText("No active network found. You can still scan this computer (127.0.0.1).");
                return;
            }
            myIpLabel.setText(info.getIp() + "/" + info.getPrefixLength());
            interfaceLabel.setText(info.getInterfaceName());
            targetField.setText(info.getSuggestedTarget());
            statusLabel.setText("Network detected. Press Scan to scan " + info.getSuggestedTarget());
        } catch (Exception ex) {
            statusLabel.setText("Could not read network settings: " + ex.getMessage());
        }
    }

    private void startScan() {
        if (nmapPath == null || runner != null) {
            return;
        }
        final String target = targetField.getText().trim();
        if (!NmapRunner.isValidTarget(target)) {
            JOptionPane.showMessageDialog(this,
                    "Please enter an IP address, a subnet or a host name.\n"
                            + "Examples: 192.168.1.0/24   192.168.1.10   192.168.1.1-50",
                    "Invalid target", JOptionPane.ERROR_MESSAGE);
            return;
        }
        final ScanSpeed speed = slowRadio.isSelected() ? ScanSpeed.SLOW : ScanSpeed.FAST;
        final Date started = new Date();

        tableModel.setRowCount(0);
        logArea.setText("");
        lastReport = null;
        setScanning(true);
        statusLabel.setText("Scanning " + target + " (" + speed + ") ...");

        runner = new NmapRunner(nmapPath);
        new SwingWorker<List<HostResult>, String>() {
            @Override
            protected List<HostResult> doInBackground() throws Exception {
                return runner.scan(target, speed, this::publish);
            }

            @Override
            protected void process(List<String> lines) {
                for (String l : lines) {
                    logArea.append(l + "\n");
                }
                logArea.setCaretPosition(logArea.getDocument().getLength());
            }

            @Override
            protected void done() {
                runner = null;
                setScanning(false);
                try {
                    List<HostResult> hosts = get();
                    long duration = System.currentTimeMillis() - started.getTime();
                    showResults(hosts);
                    lastReport = ReportBuilder.build(target, speed, started, duration, hosts);
                    saveButton.setEnabled(true);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException ex) {
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    statusLabel.setText(cause.getMessage());
                    if (!(cause.getMessage() != null && cause.getMessage().startsWith("Scan stopped"))) {
                        JOptionPane.showMessageDialog(MainWindow.this, cause.getMessage(),
                                "Scan failed", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }.execute();
    }

    private void stopScan() {
        NmapRunner r = runner;
        if (r != null) {
            r.cancel();
            statusLabel.setText("Stopping...");
        }
    }

    private void showResults(List<HostResult> hosts) {
        int openPorts = 0;
        for (HostResult h : hosts) {
            if (h.getPorts().isEmpty()) {
                tableModel.addRow(new Object[]{h.getIp(), h.getHostname(), "-", "-", "up", "no open ports", ""});
                continue;
            }
            for (PortResult p : h.getPorts()) {
                tableModel.addRow(new Object[]{
                    h.getIp(), h.getHostname(), p.getPort(), p.getProtocol(), p.getState(), p.getService(), p.getVersion()
                });
                openPorts++;
            }
        }
        statusLabel.setText("Scan finished: " + hosts.size() + " host(s) up, " + openPorts + " open port(s).");
    }

    private void setScanning(boolean scanning) {
        progress.setIndeterminate(scanning);
        scanButton.setEnabled(!scanning);
        stopButton.setEnabled(scanning);
        detectButton.setEnabled(!scanning);
        targetField.setEnabled(!scanning);
        slowRadio.setEnabled(!scanning);
        fastRadio.setEnabled(!scanning);
        saveButton.setEnabled(false);
    }

    // ------------------------------------------------------------------ save / open

    private void saveEncrypted() {
        if (lastReport == null) {
            return;
        }
        char[] password = askNewPassword();
        if (password == null) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("NetScanner encrypted report (*.enc)", "enc"));
        chooser.setSelectedFile(new File("scan-report.enc"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            Arrays.fill(password, '\0');
            return;
        }
        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".enc")) {
            file = new File(file.getParentFile(), file.getName() + ".enc");
        }
        try {
            Files.write(file.toPath(), ReportCrypto.encrypt(lastReport, password));
            statusLabel.setText("Encrypted report saved: " + file.getAbsolutePath());
            JOptionPane.showMessageDialog(this,
                    "Report saved and encrypted with AES-256.\n" + file.getAbsolutePath()
                            + "\n\nKeep the password safe - the report cannot be opened without it.",
                    "Saved", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not save the report: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void openEncrypted() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("NetScanner encrypted report (*.enc)", "enc"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        JPasswordField pf = new JPasswordField(20);
        int ok = JOptionPane.showConfirmDialog(this, new Object[]{"Password for " + file.getName() + ":", pf},
                "Open encrypted report", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        char[] password = pf.getPassword();
        try {
            String text = ReportCrypto.decrypt(Files.readAllBytes(file.toPath()), password);
            JTextArea area = new JTextArea(text, 25, 90);
            area.setEditable(false);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JOptionPane.showMessageDialog(this, new JScrollPane(area), file.getName(), JOptionPane.PLAIN_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Cannot open report", JOptionPane.ERROR_MESSAGE);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** Asks for a password twice. Returns null if cancelled. */
    private char[] askNewPassword() {
        while (true) {
            JPasswordField p1 = new JPasswordField(20);
            JPasswordField p2 = new JPasswordField(20);
            Object[] fields = {"Choose a password (at least 6 characters):", p1, "Repeat the password:", p2};
            int ok = JOptionPane.showConfirmDialog(this, fields, "Encrypt report",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (ok != JOptionPane.OK_OPTION) {
                return null;
            }
            char[] a = p1.getPassword();
            char[] b = p2.getPassword();
            if (a.length < 6) {
                JOptionPane.showMessageDialog(this, "The password must be at least 6 characters.");
            } else if (!Arrays.equals(a, b)) {
                JOptionPane.showMessageDialog(this, "The two passwords do not match.");
            } else {
                Arrays.fill(b, '\0');
                return a;
            }
            Arrays.fill(a, '\0');
            Arrays.fill(b, '\0');
        }
    }
}
