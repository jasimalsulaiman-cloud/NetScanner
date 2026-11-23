package netscanner;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Program entry point.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {
                // fall back to the default look and feel
            }
            new MainWindow().setVisible(true);
        });
    }
}
