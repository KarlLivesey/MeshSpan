// SPDX-License-Identifier: GPL-2.0-only

import { createRouter } from "@solidjs/router";

import { HomePage } from "./HomePage";
import { IdentityAdministrationPage } from "./IdentityAdministrationPage";
import { SignInPage } from "./SignInPage";

function NotFoundPage() {
  return (
    <section class="route-status">
      <p class="eyebrow">Not found</p>
      <h1>That page is not part of this appliance.</h1>
      <a href="/">Return to files</a>
    </section>
  );
}

export const AppRouter = createRouter({
  routes: [
    { component: HomePage, path: "/" },
    { component: SignInPage, path: "/sign-in" },
    { component: IdentityAdministrationPage, path: "/admin/identities" },
    { component: NotFoundPage, path: "*404" },
  ],
});
