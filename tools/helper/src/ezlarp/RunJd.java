package ezlarp;

import java.io.File;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.Enumeration;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.jd.core.v1.ClassFileToJavaSourceDecompiler;
import org.jd.core.v1.api.loader.Loader;
import org.jd.core.v1.api.printer.Printer;

/** usage: ezlarp.RunJd <ignored> <input.jar> <output.zip> [ezlarp.lib=<jar>] */
public final class RunJd {
  public static void main(String[] args) throws Exception {
    Out out = new Out(new File(args[2]));
    Throwable fatal = null;
    try {
      Map<String, String> o = Out.opts(args);
      final JarFile jar = new JarFile(args[1]);
      String lib = o.get("ezlarp.lib");
      final JarFile libJar = lib != null && !lib.isEmpty() ? new JarFile(lib) : null;
      Loader loader = new Loader() {
        JarEntry find(String internal) {
          JarEntry e = jar.getJarEntry(internal + ".class");
          if (e == null && libJar != null) e = libJar.getJarEntry(internal + ".class");
          return e;
        }
        @Override public boolean canLoad(String internal) { return find(internal) != null; }
        @Override public byte[] load(String internal) {
          try {
            JarEntry e = jar.getJarEntry(internal + ".class");
            JarFile src = jar;
            if (e == null && libJar != null) { e = libJar.getJarEntry(internal + ".class"); src = libJar; }
            if (e == null) return null;
            try (InputStream in = src.getInputStream(e)) {
              ByteArrayOutputStream b = new ByteArrayOutputStream();
              byte[] buf = new byte[8192];
              for (int r; (r = in.read(buf)) > 0;) b.write(buf, 0, r);
              return b.toByteArray();
            }
          } catch (Exception ex) { return null; }
        }
      };
      ClassFileToJavaSourceDecompiler jd = new ClassFileToJavaSourceDecompiler();
      for (Enumeration<JarEntry> en = jar.entries(); en.hasMoreElements();) {
        String n = en.nextElement().getName();
        if (!n.endsWith(".class") || n.startsWith("META-INF/")) continue;
        String internal = n.substring(0, n.length() - 6);
        if (internal.contains("$")) continue;
        try {
          TextPrinter p = new TextPrinter();
          jd.decompile(loader, p, internal);
          out.source(internal + ".java", p.toString());
        } catch (Throwable t) {
          out.error(internal + ": " + Out.stack(t));
        }
      }
    } catch (Throwable t) {
      fatal = t;
    } finally {
      out.finish("jd", fatal);
    }
  }

  /** Plain-text printer (JD-Core only hands over tokens). */
  static final class TextPrinter implements Printer {
    private final StringBuilder sb = new StringBuilder();
    private int indent = 0;
    @Override public void start(int maxLineNumber, int majorVersion, int minorVersion) {}
    @Override public void end() {}
    @Override public void printText(String text) { sb.append(text); }
    @Override public void printNumericConstant(String constant) { sb.append(constant); }
    @Override public void printStringConstant(String constant, String ownerInternalName) { sb.append(constant); }
    @Override public void printKeyword(String keyword) { sb.append(keyword); }
    @Override public void printDeclaration(int type, String internalTypeName, String name, String descriptor) { sb.append(name); }
    @Override public void printReference(int type, String internalTypeName, String name, String descriptor, String ownerInternalName) { sb.append(name); }
    @Override public void indent() { indent++; }
    @Override public void unindent() { if (indent > 0) indent--; }
    @Override public void startLine(int lineNumber) { for (int i = 0; i < indent; i++) sb.append("    "); }
    @Override public void endLine() {
      int n = sb.length();
      while (n > 0 && sb.charAt(n - 1) == ' ') n--;
      sb.setLength(n);
      sb.append('\n');
    }
    @Override public void extraLine(int count) { while (count-- > 0) sb.append('\n'); }
    @Override public void startMarker(int type) {}
    @Override public void endMarker(int type) {}
    @Override public String toString() { return sb.toString(); }
  }
}
