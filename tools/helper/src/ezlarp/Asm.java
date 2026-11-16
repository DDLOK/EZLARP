package ezlarp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceClassVisitor;

/**
 * EZLARP bytecode listing (ASM Textifier, runs inside CheerpJ).
 *
 * usage: ezlarp.Asm <input.jar> <output.zip>
 *
 * For every .class in the input, writes "src/<entry>.txt" with a readable
 * bytecode dump.
 */
public final class Asm {

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println("usage: ezlarp.Asm <input.jar> <output.zip>");
      return;
    }
    File out = new File(args[1]);
    File dir = out.getParentFile();
    if (dir != null) {
      dir.mkdirs();
      File[] old = dir.listFiles();
      if (old != null) for (File f : old) if (!f.equals(out)) f.delete();
    }
    int n = 0;
    try (ZipFile in = new ZipFile(args[0]); ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(out))) {
      Enumeration<? extends ZipEntry> en = in.entries();
      while (en.hasMoreElements()) {
        ZipEntry e = en.nextElement();
        if (e.isDirectory() || !e.getName().endsWith(".class")) continue;
        String text;
        try (InputStream is = in.getInputStream(e)) {
          ByteArrayOutputStream bos = new ByteArrayOutputStream();
          byte[] buf = new byte[8192];
          for (int r; (r = is.read(buf)) > 0;) bos.write(buf, 0, r);
          StringWriter sw = new StringWriter();
          PrintWriter pw = new PrintWriter(sw);
          new ClassReader(bos.toByteArray()).accept(new TraceClassVisitor(null, new Textifier(), pw), 0);
          pw.flush();
          text = sw.toString();
        } catch (Throwable t) {
          text = "// could not read " + e.getName() + ": " + t + "\n";
        }
        zip.putNextEntry(new ZipEntry("src/" + e.getName() + ".txt"));
        zip.write(text.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
        n++;
      }
    }
    System.out.println("EZD " + n);
  }
}
