// SPDX-License-Identifier: GPL-2.0-only

import { createRouter } from "@solidjs/router";

import { HomePage } from "./HomePage";
import { IdentityAdministrationPage } from "./IdentityAdministrationPage";
import { OperationAdministrationPage } from "./OperationAdministrationPage";
import { SecurityPage } from "./SecurityPage";
import { SignInPage } from "./SignInPage";
import { VolumeAdministrationPage } from "./VolumeAdministrationPage";

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
    { component: SecurityPage, path: "/security" },
    { component: IdentityAdministrationPage, path: "/admin/identities" },
    { component: OperationAdministrationPage, path: "/admin/operations" },
    { component: VolumeAdministrationPage, path: "/admin/volumes" },
    { component: NotFoundPage, path: "*404" },
  ],
});
