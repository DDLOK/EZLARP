package demo.mod;

import java.net.URL;
import net.minecraft.client.session.Session;

/**
 * Exists only so the EZLARP threat scan has something to flag.
 * Nothing here is ever called and nothing is sent anywhere: the webhook
 * address is a made-up placeholder and the methods have no callers.
 */
final class ScanDemo {
  static final String NOTE = "EZLARP scan demo: inert placeholders, not real endpoints";
  static final String FAKE_WEBHOOK = "https://discord.com/api/webhooks/000000000000000000/EZLARP-DEMO-NOT-A-REAL-WEBHOOK";
  static final String FAKE_IP_LOOKUP = "https://api.ipify.org/?demo=ezlarp";

  private ScanDemo() {}

  static int tokenLength(Session session) {
    return session.getAccessToken().length();
  }

  static Object openExample() throws Exception {
    return new URL("https://example.com/").openConnection();
  }

  static Process echo() throws Exception {
    return Runtime.getRuntime().exec(new String[] {"echo", "ezlarp demo"});
  }
}
