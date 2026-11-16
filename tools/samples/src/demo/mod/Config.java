package demo.mod;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public final class Config {
  private final Properties props = new Properties();
  private final Path file;

  public Config(Path dir) {
    this.file = dir.resolve("ezlarp-sample.properties");
  }

  public void load() throws IOException {
    if (Files.exists(file)) {
      try (var in = Files.newInputStream(file)) {
        props.load(in);
      }
    }
  }

  public boolean flag(String key, boolean fallback) {
    return Boolean.parseBoolean(props.getProperty(key, Boolean.toString(fallback)));
  }

  public int number(String key, int fallback) {
    try {
      return Integer.parseInt(props.getProperty(key, Integer.toString(fallback)));
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
