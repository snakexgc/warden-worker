/**
 * JS wrapper entry point.
 *
 * Route selected hot-path APIs to HEAVY_DO to avoid Worker CPU timeout,
 * while keeping the rest of requests on the Rust WASM worker.
 */

import RustWorker from "../build/index.js";
import {
  getHeavyDoName,
  normalizePathname,
  shouldOffloadToHeavyDo,
} from "./heavy_do_routing.mjs";

const FIXED_LENGTH_HEADER = "x-warden-fixed-length";

function applyFixedLengthStream(response, ctx) {
  const rawLength = response.headers.get(FIXED_LENGTH_HEADER);
  if (rawLength === null) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.delete(FIXED_LENGTH_HEADER);
  const length = Number(rawLength);
  if (!response.body || !Number.isSafeInteger(length) || length < 0) {
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  const fixed = new FixedLengthStream(length);
  const piping = response.body.pipeTo(fixed.writable);
  ctx.waitUntil(
    piping.catch((error) => {
      console.warn("fixed-length response stream failed", error);
    }),
  );
  return new Response(fixed.readable, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);

    if (env.HEAVY_DO && shouldOffloadToHeavyDo(url.pathname)) {
      const stub = env.HEAVY_DO.getByName(await getHeavyDoName(request));
      return stub.fetch(request);
    }

    const worker = new RustWorker(ctx, env);
    const response = await worker.fetch(request);
    return applyFixedLengthStream(response, ctx);
  },

  async scheduled(event, env, ctx) {
    const worker = new RustWorker(ctx, env);
    return worker.scheduled(event);
  },
};

export { NotificationsHub, HeavyDo } from "../build/index.js";
