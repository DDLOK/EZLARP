package demo.mod.mixin;

/** Stand-in for a Mixin class (the real one would carry @Mixin(TitleScreen.class)). */
public abstract class TitleScreenMixin {
  protected void ezlarp$onInit() {
    System.out.println("title screen opened");
  }
}
