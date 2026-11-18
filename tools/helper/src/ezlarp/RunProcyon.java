package ezlarp;

import java.io.File;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import com.strobel.assembler.metadata.ClasspathTypeLoader;
import com.strobel.assembler.metadata.CompositeTypeLoader;
import com.strobel.assembler.metadata.ITypeLoader;
import com.strobel.assembler.metadata.JarTypeLoader;
import com.strobel.decompiler.Decompiler;
import com.strobel.decompiler.DecompilerSettings;
import com.strobel.decompiler.PlainTextOutput;

/** usage: ezlarp.RunProcyon <ignored> <input.jar> <output.zip> [ezlarp.lib=<jar>] */
public final class RunProcyon {
  public static void main(String[] args) throws Exception {
    Out out = new Out(new File(args[2]));
    Throwable fatal = null;
    try {
      Map<String, String> o = Out.opts(args);
      List<ITypeLoader> loaders = new ArrayList<>();
      JarFile jar = new JarFile(args[1]);
      loaders.add(new JarTypeLoader(jar));
      String lib = o.get("ezlarp.lib");
      if (lib != null && !lib.isEmpty()) loaders.add(new JarTypeLoader(new JarFile(lib)));
      loaders.add(new ClasspathTypeLoader());
      DecompilerSettings settings = DecompilerSettings.javaDefaults();
      settings.setTypeLoader(new CompositeTypeLoader(loaders.toArray(new ITypeLoader[0])));
      settings.setForceExplicitImports(true);
      for (Enumeration<JarEntry> en = jar.entries(); en.hasMoreElements();) {
        String n = en.nextElement().getName();
        if (!n.endsWith(".class") || n.startsWith("META-INF/")) continue;
        String internal = n.substring(0, n.length() - 6);
        if (internal.contains("$")) continue; // inner classes come out with their outer class
        try {
          PlainTextOutput text = new PlainTextOutput();
          Decompiler.decompile(internal, text, settings);
          out.source(internal + ".java", text.toString());
        } catch (Throwable t) {
          out.error(internal + ": " + Out.stack(t));
        }
      }
    } catch (Throwable t) {
      fatal = t;
    } finally {
      out.finish("procyon", fatal);
    }
  }
}
