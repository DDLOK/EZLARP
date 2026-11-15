import { Container, getContainer } from "@cloudflare/containers";

export class Backend extends Container {
  defaultPort = 8787;
  sleepAfter = "10m";
  enableInternet = false;

  constructor(ctx, env) {
    super(ctx, env);
    this.envVars = {
      BACKEND_KEY: env.BACKEND_KEY || "",
      PORT: "8787",
    };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/decompile" && request.method === "POST") {
      const container = getContainer(env.BACKEND);
      const forwarded = new Request("http://container/decompile", {
        method: "POST",
        headers: {
          "content-type": request.headers.get("content-type") || "application/octet-stream",
          "x-ezlarp-key": env.BACKEND_KEY || "",
        },
        body: request.body,
      });
      return container.fetch(forwarded);
    }

    if (url.pathname === "/api/health") {
      return getContainer(env.BACKEND).fetch(new Request("http://container/health"));
    }

    return env.ASSETS.fetch(request);
  },
};
