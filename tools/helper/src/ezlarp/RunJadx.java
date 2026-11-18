package ezlarp;

import java.io.File;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import jadx.api.CommentsLevel;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * usage: ezlarp.RunJadx <ignored> <input.jar|.dex|.apk> <output.zip> [ezlarp.only=<names.txt>] [ezlarp.lib=<jar>]
 * JADX reads Android dex directly (no dex2jar), and plain jars through its class-file input.
 */
public final class RunJadx {
  public static void main(String[] args) throws Exception {
    Out out = new Out(new File(args[2]));
    Throwable fatal = null;
    try {
      Map<String, String> o = Out.opts(args);
      final Set<String> only = Out.only(o);
      JadxArgs ja = new JadxArgs();
      ja.setInputFiles(Collections.singletonList(new File(args[1])));
      ja.setThreadsCount(1);
      ja.setSkipResources(true);
      ja.setShowInconsistentCode(true);
      ja.setCommentsLevel(CommentsLevel.WARN);
      ja.setDebugInfo(true);
      ja.setUseImports(true);
      ja.setInlineAnonymousClasses(true);
      ja.setRespectBytecodeAccModifiers(false);
      if ("1".equals(o.get("ezlarp.deobf"))) {
        ja.setDeobfuscationOn(true);
        ja.setDeobfuscationMinLength(3);
      }
      if (only != null) ja.setClassFilter(name -> only.contains(name.replace('.', '/')) || only.contains(topLevel(name).replace('.', '/')));
      try (JadxDecompiler jadx = new JadxDecompiler(ja)) {
        jadx.load();
        for (JavaClass cls : jadx.getClasses()) {
          String raw = cls.getClassNode().getClassInfo().getRawName().replace('.', '/');
          if (only != null && !only.contains(raw)) continue;
          try {
            out.source(raw + ".java", cls.getCode());
          } catch (Throwable t) {
            out.error(raw + ": " + Out.stack(t));
          }
        }
      }
    } catch (Throwable t) {
      fatal = t;
    } finally {
      out.finish("jadx", fatal);
    }
  }

  private static String topLevel(String name) {
    int i = name.indexOf('$');
    return i < 0 ? name : name.substring(0, i);
  }
}
