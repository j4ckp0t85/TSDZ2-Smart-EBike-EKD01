import java.awt.Component;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.imageio.ImageIO;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;

public class ConfiguratorSocPercentModeTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static Object field(TSDZ2_Configurator configurator, String name) throws Exception {
        Field field = TSDZ2_Configurator.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(configurator);
    }

    private static List<String> writeFlags(TSDZ2_Configurator configurator, boolean enabled) {
        StringWriter settings = new StringWriter();
        StringWriter config = new StringWriter();
        configurator.writeEkd01SocSettings(new PrintWriter(settings), new PrintWriter(config));
        check(settings.toString().trim().equals("false" + System.lineSeparator() + enabled),
                "Preset compatibility slot or direct-SOC flag mismatch");
        check(config.toString().trim().equals("#define EKD01_SOC_PERCENT_MODE " + (enabled ? "1" : "0")),
                "Generated header must contain only the direct-SOC define");
        return List.of(settings.toString().trim().split("\\R"));
    }

    private static void runTests() throws Exception {
        List<String> legacy = Files.readAllLines(Paths.get("experimental settings", "20261009-165544CEST.ini"),
                StandardCharsets.UTF_8);
        check(legacy.size() == 161, "Legacy preset fixture changed");
        Path saved = Files.createTempFile("configurator-soc-percent-", ".ini");
        TSDZ2_Configurator configurator = new TSDZ2_Configurator();
        try {
            JCheckBox percent = (JCheckBox)field(configurator, "CB_EKD01_SOC_PERCENT_MODE");
            JComboBox<?> display = (JComboBox<?>)field(configurator, "JCB_DISPLAY_TYPE");
            JComboBox<?> motor = (JComboBox<?>)field(configurator, "JCB_MOTOR_TYPE");
            Path legacyFixture = Paths.get("experimental settings", "20261009-165544CEST.ini");
            configurator.loadSettings(legacyFixture.toFile());
            check(!percent.isSelected(), "Legacy presets must leave direct SOC off");
            writeFlags(configurator, false);

            List<String> oldPreset = new ArrayList<>(legacy);
            oldPreset.add("true");
            Files.write(saved, oldPreset, StandardCharsets.UTF_8);
            percent.setSelected(true);
            configurator.loadSettings(saved.toFile());
            check(!percent.isSelected(), "Retired preset flag must not enable direct SOC");
            writeFlags(configurator, false);

            display.setSelectedIndex(TSDZ2_Configurator.EKD01);
            motor.setSelectedIndex(TSDZ2_Configurator.TSDZ2_48V);
            percent.doClick();
            check(percent.isSelected() && percent.isEnabled(), "Direct-SOC option must be selectable");
            List<String> directPreset = new ArrayList<>(legacy);
            directPreset.addAll(writeFlags(configurator, true));
            Files.write(saved, directPreset, StandardCharsets.UTF_8);
            percent.setSelected(false);
            configurator.loadSettings(saved.toFile());
            check(percent.isSelected(), "Enabled direct-SOC preset did not round-trip");
            writeFlags(configurator, true);

            directPreset.set(legacy.size(), "true");
            Files.write(saved, directPreset, StandardCharsets.UTF_8);
            configurator.loadSettings(saved.toFile());
            check(percent.isSelected(), "Old compatibility slot must not override direct SOC");
            writeFlags(configurator, true);

            configurator.boolTSDZ8headerRead = true;
            motor.setSelectedIndex(TSDZ2_Configurator.TSDZ8);
            check(!percent.isEnabled() && !percent.isSelected(), "TSDZ8 must clear and disable direct SOC");
            percent.setSelected(true);
            writeFlags(configurator, false);
            percent.setSelected(false);
            motor.setSelectedIndex(TSDZ2_Configurator.TSDZ2_48V);
            check(percent.isEnabled() && !percent.isSelected(), "Returning to TSDZ2 must not silently opt in");

            for (int type = TSDZ2_Configurator.VLCD5; type < TSDZ2_Configurator.EKD01; ++type) {
                display.setSelectedIndex(TSDZ2_Configurator.EKD01);
                percent.setSelected(true);
                display.setSelectedIndex(type);
                check(!percent.isEnabled() && !percent.isSelected(), "Non-EKD01 must clear and disable direct SOC");
                percent.setSelected(true);
                writeFlags(configurator, false);
                percent.setSelected(false);
            }

            display.setSelectedIndex(TSDZ2_Configurator.EKD01);
            directPreset = new ArrayList<>(legacy);
            directPreset.addAll(writeFlags(configurator, false));
            Files.write(saved, directPreset, StandardCharsets.UTF_8);
            percent.setSelected(true);
            configurator.loadSettings(saved.toFile());
            check(!percent.isSelected(), "Disabled preset did not round-trip");
            percent.setSelected(true);
            configurator.loadSettings(legacyFixture.toFile());
            check(!percent.isSelected(), "Loading a legacy preset must clear a previous opt-in");

            percent.setSelected(true);
            configurator.setVisible(true);
            configurator.validate();
            check(percent.isShowing(), "Direct-SOC option is not visible");
            for (Component ancestor = percent.getParent(); ancestor != null; ancestor = ancestor.getParent()) {
                java.awt.Rectangle bounds = SwingUtilities.convertRectangle(percent.getParent(), percent.getBounds(), ancestor);
                check(ancestor.contains(bounds.x, bounds.y)
                        && ancestor.contains(bounds.x + bounds.width - 1, bounds.y + bounds.height - 1),
                        "Direct-SOC option clipped by " + ancestor.getClass().getSimpleName());
            }
            check(percent.getWidth() >= percent.getPreferredSize().width, "Direct-SOC label is clipped");
            for (Component sibling : percent.getParent().getComponents()) {
                if (sibling != percent && sibling.isVisible()) {
                    check(!percent.getBounds().intersects(sibling.getBounds()), "Direct-SOC option overlaps another control");
                }
            }
            BufferedImage screenshot = new BufferedImage(configurator.getWidth(), configurator.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D graphics = screenshot.createGraphics();
            configurator.paintAll(graphics);
            graphics.dispose();
            ImageIO.write(screenshot, "png", Paths.get("bin", "configurator-soc-percent.png").toFile());
            System.out.println("PASS: direct-SOC presets/defines, older preset compatibility, motor/display gating, Nimbus visibility");
        } finally {
            configurator.dispose();
            Files.deleteIfExists(saved);
        }
    }

    public static void main(String[] args) throws Exception {
        for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
            if ("Nimbus".equals(info.getName())) {
                javax.swing.UIManager.setLookAndFeel(info.getClassName());
                break;
            }
        }
        SwingUtilities.invokeAndWait(() -> {
            try {
                runTests();
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });
    }
}