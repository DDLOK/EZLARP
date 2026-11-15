package ezlarp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.api.SinkReturns;
import org.jetbrains.java.decompiler.main.Fernflower;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;
import org.jetbrains.java.decompiler.main.extern.IResultSaver;

/**
 * EZLARP in-browser decompile driver (runs inside CheerpJ).
 *
 * usage: ezlarp.Run <vf|cfr> <input.jar|input.class> <output.zip>
 *
 * Writes every decompiled source to output.zip under "src/", plus
 * "ezlarp/log.txt" with warnings and errors. Prints "EZP <n>" to stdout
 * after each class so the page can show progress.
 */
public final class Run {

  private static ZipOutputStream zip;
  private static final Set<String> written = new HashSet<>();
  private static final StringBuilder log = new StringBuilder();
  private static int count = 0; // reset at the start of every run

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      System.err.println("usage: ezlarp.Run <vf|cfr> <input> <output.zip>");
      return;
    }
    // the JVM stays alive between runs inside the page, so reset static state
    written.clear();
    log.setLength(0);
    count = 0;
    String engine = args[0];
    File in = new File(args[1]);
    File out = new File(args[2]);

    File dir = out.getParentFile();
    if (dir != null) {
      dir.mkdirs();
      File[] old = dir.listFiles();
      if (old != null) for (File f : old) if (!f.equals(out)) f.delete();
    }

    Throwable fatal = null;
    zip = new ZipOutputStream(new FileOutputStream(out));
    try {
      if ("cfr".equals(engine)) runCfr(in);
      else runVineflower(in);
    } catch (Throwable t) {
      fatal = t;
      log.append("[fatal] ").append(stack(t)).append('\n');
    } finally {
      put("ezlarp/log.txt", log.toString());
      put("ezlarp/info.txt", "engine=" + engine + "\nclasses=" + count + "\n");
      zip.close();
    }
    System.out.println("EZD " + count);
    // no System.exit(): it would tear down the in-page JVM used by later runs
  }

  // ---------------------------------------------------------------- vineflower

  private static void runVineflower(File in) throws Exception {
    Map<String, Object> opts = new HashMap<>();
    opts.put("log-level", "warn");
    opts.put("thread-count", "1");
    opts.put("decompile-generics", "1");
    opts.put("remove-synthetic", "1");
    opts.put("dump-code-lines", "0");
    opts.put("indent-string", "    ");

    IResultSaver saver = new IResultSaver() {
      @Override public void saveFolder(String path) {}
      @Override public void copyFile(String source, String path, String entryName) {}
      @Override public void createArchive(String path, String archiveName, Manifest manifest) {}
      @Override public void saveDirEntry(String path, String archiveName, String entryName) {}
      @Override public void copyEntry(String source, String path, String archiveName, String entry) {}
      @Override public void closeArchive(String path, String archiveName) {}

      @Override
      public void saveClassFile(String path, String qualifiedName, String entryName, String content, int[] mapping) {
        String name = qualifiedName != null ? qualifiedName + ".java" : entryName;
        saveSource(name, content);
      }

      @Override
      public void saveClassEntry(String path, String archiveName, String qualifiedName, String entryName, String content) {
        saveSource(entryName != null ? entryName : qualifiedName + ".java", content);
      }
    };

    IFernflowerLogger logger = new IFernflowerLogger() {
      @Override
      public void writeMessage(String message, Severity severity) {
        if (severity == Severity.WARN || severity == Severity.ERROR) {
          synchronized (log) { log.append('[').append(severity).append("] ").append(message).append('\n'); }
        }
      }

      @Override
      public void writeMessage(String message, Severity severity, Throwable t) {
        writeMessage(message + (t != null ? "\n" + stack(t) : ""), severity);
      }
    };

    Fernflower ff = new Fernflower(saver, opts, logger);
    try {
      ff.addSource(in);
      ff.decompileContext();
    } finally {
      ff.clearContext();
    }
  }

  // ---------------------------------------------------------------- cfr

  private static void runCfr(File in) {
    Map<String, String> opts = new HashMap<>();
    opts.put("silent", "true");
    opts.put("comments", "true");

    OutputSinkFactory sinks = new OutputSinkFactory() {
      @Override
      public List<SinkClass> getSupportedSinks(SinkType type, Collection<SinkClass> available) {
        if (type == SinkType.JAVA && available.contains(SinkClass.DECOMPILED)) {
          List<SinkClass> l = new ArrayList<>();
          l.add(SinkClass.DECOMPILED);
          l.add(SinkClass.STRING);
          return l;
        }
        if (type == SinkType.EXCEPTION && available.contains(SinkClass.EXCEPTION_MESSAGE)) {
          return Collections.singletonList(SinkClass.EXCEPTION_MESSAGE);
        }
        return Collections.singletonList(SinkClass.STRING);
      }

      @Override
      @SuppressWarnings("unchecked")
      public <T> Sink<T> getSink(SinkType type, SinkClass cls) {
        if (type == SinkType.JAVA && cls == SinkClass.DECOMPILED) {
          return x -> {
            SinkReturns.Decompiled d = (SinkReturns.Decompiled) x;
            String pkg = d.getPackageName();
            String name = (pkg == null || pkg.isEmpty() ? "" : pkg.replace('.', '/') + "/") + d.getClassName() + ".java";
            saveSource(name, d.getJava());
          };
        }
        if (type == SinkType.EXCEPTION && cls == SinkClass.EXCEPTION_MESSAGE) {
          return x -> {
            SinkReturns.ExceptionMessage m = (SinkReturns.ExceptionMessage) x;
            synchronized (log) { log.append("[ERROR] ").append(m.getPath()).append(": ").append(m.getMessage()).append('\n'); }
          };
        }
        if (type == SinkType.EXCEPTION) {
          return x -> { synchronized (log) { log.append("[ERROR] ").append(x).append('\n'); } };
        }
        return x -> {};
      }
    };

    CfrDriver driver = new CfrDriver.Builder().withOptions(opts).withOutputSink(sinks).build();
    driver.analyse(Collections.singletonList(in.getPath()));
  }

  // ---------------------------------------------------------------- output

  private static synchronized void saveSource(String name, String content) {
    if (content == null) {
      log.append("[ERROR] failed to decompile ").append(name).append('\n');
      return;
    }
    if (name.startsWith("/")) name = name.substring(1);
    put("src/" + name, content);
    count++;
    System.out.println("EZP " + count);
  }

  private static synchronized void put(String name, String content) {
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

  private static String stack(Throwable t) {
    StringWriter sw = new StringWriter();
    t.printStackTrace(new PrintWriter(sw));
    String s = sw.toString();
    return s.length() > 4000 ? s.substring(0, 4000) + "\n..." : s;
  }
}
