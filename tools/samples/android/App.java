package demo;
import java.util.*;
public class App {
  interface Greeter { String greet(String n); }
  static class Loud implements Greeter { public String greet(String n){ return "HELLO " + n.toUpperCase(); } }
  private final Map<String,Integer> counts = new HashMap<>();
  public int bump(String k){ Integer c = counts.get(k); int v = c == null ? 1 : c + 1; counts.put(k, v); return v; }
  public static void main(String[] a){
    Greeter g = new Loud();
    App app = new App();
    for (String s : a) { System.out.println(g.greet(s) + " #" + app.bump(s)); }
    try { Thread.sleep(10); } catch (InterruptedException e) { throw new RuntimeException(e); }
  }
}
