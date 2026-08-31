// SPDX-License-Identifier: GPL-2.0-only

import { render } from "@solidjs/web";

import { AppLayout } from "./app/AppLayout";
import { AppRouter } from "./app/router";
import { SessionProvider } from "./app/session";
import { createMeshSpanFetchClient } from "./generated/fetch.gen";
import "./styles/app.css";

const mount = document.querySelector("#app");
if (mount === null) {
  throw new Error("MeshSpan application mount is absent");
}

const client = createMeshSpanFetchClient({
  baseUrl: new URL("/api/latest/", window.location.href).href,
});

render(
  () => (
    <SessionProvider client={client}>
      <AppRouter>
        {(route) => <AppLayout>{route.children}</AppLayout>}
      </AppRouter>
    </SessionProvider>
  ),
  mount,
);
