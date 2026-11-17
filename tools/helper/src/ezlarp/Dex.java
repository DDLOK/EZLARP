package ezlarp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import com.googlecode.d2j.dex.ClassVisitorFactory;
import com.googlecode.d2j.dex.DexExceptionHandler;
import com.googlecode.d2j.dex.ExDex2Asm;
import com.googlecode.d2j.dex.LambadaNameSafeClassAdapter;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.reader.DexFileReader;
import com.googlecode.dex2jar.ir.IrMethod;

/**
 * EZLARP dex -> jar converter (dex2jar, runs inside CheerpJ).
 *
 * usage: ezlarp.Dex <classes.dex> <output.jar> [classes.txt]
 *
 * With classes.txt (one internal class name per line, e.g. com/foo/Bar$1),
 * only those classes are converted. That keeps memory low for huge apps:
 * the page converts just the classes being opened.
 *
 * Writes classes straight into the output zip (no temp directory), plus
 * "ezlarp/log.txt". Prints "EZP <n>" after each class.
 */
public final class Dex {

  private static ZipOutputStream zip;
  private static final Set<String> written = new HashSet<>();
  private static final StringBuilder log = new StringBuilder();
  private static int count;

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println("usage: ezlarp.Dex <classes.dex> <output.jar>");
      return;
    }
    written.clear();
    log.setLength(0);
    count = 0;

    File out = new File(args[1]);
    File dir = out.getParentFile();
    if (dir != null) {
      dir.mkdirs();
      File[] old = dir.listFiles();
      if (old != null) for (File f : old) if (!f.equals(out)) f.delete();
    }

    zip = new ZipOutputStream(new FileOutputStream(out));
    zip.setLevel(1);
    try {
      Set<String> only = null;
      if (args.length > 2) {
        only = new HashSet<>();
        List<String> lines = Files.readAllLines(new File(args[2]).toPath(), StandardCharsets.UTF_8);
        for (String l : lines) if (!l.trim().isEmpty()) only.add("L" + l.trim() + ";");
      }
      convert(Files.readAllBytes(new File(args[0]).toPath()), only);
    } catch (Throwable t) {
      log.append("[fatal] ").append(stack(t)).append('\n');
    } finally {
      put("ezlarp/log.txt", log.toString().getBytes(StandardCharsets.UTF_8));
      zip.close();
    }
    System.out.println("EZD " + count);
  }

  private static void convert(byte[] dex, final Set<String> only) throws Exception {
    final DexExceptionHandler handler = new DexExceptionHandler() {
      @Override
      public void handleFileException(Exception e) {
        log.append("[ERROR] ").append(e).append('\n');
      }

      @Override
      public void handleMethodTranslateException(com.googlecode.d2j.Method method, DexMethodNode node, MethodVisitor mv, Exception e) {
        log.append("[WARN] could not translate ").append(method).append(": ").append(e).append('\n');
        // keep the class loadable: make the method throw instead of leaving it without code
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/RuntimeException");
        mv.visitInsn(Opcodes.DUP);
        mv.visitLdcInsn("d2j failed to translate: " + e);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "(Ljava/lang/String;)V", false);
        mv.visitInsn(Opcodes.ATHROW);
      }
    };

    DexFileReader reader = new DexFileReader(dex);
    DexFileNode fileNode = new DexFileNode() {
      @Override
      public com.googlecode.d2j.visitors.DexClassVisitor visit(int access, String className, String superClass, String[] interfaces) {
        if (only != null && !only.contains(className)) return null; // skip: not requested
        return super.visit(access, className, superClass, interfaces);
      }
    };
    try {
      reader.accept(fileNode, DexFileReader.SKIP_DEBUG | DexFileReader.IGNORE_READ_EXCEPTION);
    } catch (Exception e) {
      handler.handleFileException(e);
    }

    ClassVisitorFactory cvf = new ClassVisitorFactory() {
      @Override
      public ClassVisitor create(String name) {
        final ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        final LambadaNameSafeClassAdapter rca = new LambadaNameSafeClassAdapter(cw);
        return new ClassVisitor(Opcodes.ASM9, rca) {
          @Override
          public void visitEnd() {
            super.visitEnd();
            String className = rca.getClassName();
            try {
              put(className + ".class", cw.toByteArray());
              count++;
              System.out.println("EZP " + count);
            } catch (Throwable t) {
              log.append("[ERROR] could not write ").append(className).append(": ").append(t).append('\n');
            }
          }
        };
      }
    };

    new ExDex2Asm(handler) {
      @Override
      public void optimize(IrMethod irMethod) {
        T_cleanLabel.transform(irMethod);
        T_deadCode.transform(irMethod);
        T_removeLocal.transform(irMethod);
        T_removeConst.transform(irMethod);
        T_zero.transform(irMethod);
        if (T_npe.transformReportChanged(irMethod)) {
          T_deadCode.transform(irMethod);
          T_removeLocal.transform(irMethod);
          T_removeConst.transform(irMethod);
        }
        T_new.transform(irMethod);
        T_fillArray.transform(irMethod);
        T_agg.transform(irMethod);
        T_multiArray.transform(irMethod);
        T_voidInvoke.transform(irMethod);
        T_deadCode.transform(irMethod);
        T_removeLocal.transform(irMethod);
        T_removeConst.transform(irMethod);
        T_type.transform(irMethod);
        T_unssa.transform(irMethod);
        T_ir2jRegAssign.transform(irMethod);
        T_trimEx.transform(irMethod);
      }
    }.convertDex(fileNode, cvf);
  }

  private static synchronized void put(String name, byte[] data) throws java.io.IOException {
    if (!written.add(name)) return;
    zip.putNextEntry(new ZipEntry(name));
    zip.write(data);
    zip.closeEntry();
  }

  private static String stack(Throwable t) {
    StringWriter sw = new StringWriter();
    t.printStackTrace(new PrintWriter(sw));
    String s = sw.toString();
    return s.length() > 4000 ? s.substring(0, 4000) + "\n..." : s;
  }
}
