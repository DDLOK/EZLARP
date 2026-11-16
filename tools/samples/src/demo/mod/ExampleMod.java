package demo.mod;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Entry point of the EZLARP sample mod. Everything in this jar is inert demo code. */
public class ExampleMod {
  public static final String MOD_ID = "ezlarp-sample";
  private final List<Feature> features = new ArrayList<>();

  public void onInitialize() {
    Config config = new Config(Path.of("config"));
    try {
      config.load();
    } catch (java.io.IOException e) {
      System.out.println("[" + MOD_ID + "] using default config");
    }
    features.add(new Feature("auto-sort", config.flag("auto-sort", true)));
    features.add(new Feature("chest-search", config.flag("chest-search", false)));
    for (Feature f : features) {
      System.out.println("[" + MOD_ID + "] " + f.describe());
    }
  }

  public long enabledCount() {
    return features.stream().filter(Feature::enabled).count();
  }

  public record Feature(String name, boolean enabled) {
    String describe() {
      return switch (name) {
        case "auto-sort" -> "sorts your inventory";
        case "chest-search" -> "highlights chests containing an item";
        default -> "unknown feature " + name;
      } + (enabled ? " (on)" : " (off)");
    }
  }
}
