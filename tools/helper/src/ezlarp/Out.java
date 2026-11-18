package ezlarp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Shared output for the engine drivers: same zip layout and progress lines as ezlarp.Run. */
final class Out {
  private final ZipOutputStream zip;
  private final Set<String> written = new HashSet<>();
  final StringBuilder log = new StringBuilder();
  int count = 0;

  Out(File out) throws IOException {
    File dir = out.getParentFile();
    if (dir != null) {
      dir.mkdirs();
      File[] old = dir.listFiles();
      if (old != null) for (File f : old) if (!f.equals(out)) f.delete();
    }
    zip = new ZipOutputStream(new FileOutputStream(out));
  }

  synchronized void source(String name, String content) {
    if (content == null || content.isEmpty()) { error("failed to decompile " + name); return; }
    if (name.startsWith("/")) name = name.substring(1);
    put("src/" + name, content);
    count++;
    System.out.println("EZP " + count);
  }

  synchronized void error(String msg) { log.append("[ERROR] ").append(msg).append('\n'); }
  synchronized void warn(String msg) { log.append("[WARN] ").append(msg).append('\n'); }

  synchronized void put(String name, String content) {
    try {
      String n = name;
      int i = 2;
      while (written.contains(n)) n = name + "." + (i++);
      written.add(n);
      zip.putNextEntry(new ZipEntry(n));
      zip.write(content.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    } catch (IOException e) {
      log.append("[ERROR] zip write ").append(name).append(": ").append(e).append('\n');
    }
  }

  void finish(String engine, Throwable fatal) throws IOException {
    if (fatal != null) log.append("[fatal] ").append(stack(fatal)).append('\n');
    put("ezlarp/log.txt", log.toString());
    put("ezlarp/info.txt", "engine=" + engine + "\nclasses=" + count + "\n");
    zip.close();
    System.out.println("EZD " + count);
  }

  /** key=value arguments after the first three */
  static Map<String, String> opts(String[] args) {
    Map<String, String> m = new HashMap<>();
    for (int i = 3; i < args.length; i++) {
      int eq = args[i].indexOf('=');
      if (eq > 0) m.put(args[i].substring(0, eq), args[i].substring(eq + 1));
    }
    return m;
  }

  /** class names (internal form, one per line) from an "ezlarp.only" file, or null */
  static Set<String> only(Map<String, String> opts) throws IOException {
    String f = opts.get("ezlarp.only");
    if (f == null || f.isEmpty()) return null;
    Set<String> s = new LinkedHashSet<>();
    for (String line : new String(Files.readAllBytes(new File(f).toPath()), StandardCharsets.UTF_8).split("\n")) {
      line = line.trim();
      if (!line.isEmpty()) s.add(line.replace('.', '/'));
    }
    return s;
  }

  static String stack(Throwable t) {
    StringWriter sw = new StringWriter();
    t.printStackTrace(new PrintWriter(sw));
    String s = sw.toString();
    return s.length() > 4000 ? s.substring(0, 4000) + "\n..." : s;
  }
}
