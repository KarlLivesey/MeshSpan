// SPDX-License-Identifier: GPL-2.0-only

import { createRouter } from "@solidjs/router";

import { CertificateAdministrationPage } from "./CertificateAdministrationPage";
import { HomePage } from "./HomePage";
import { IdentityAdministrationPage } from "./IdentityAdministrationPage";
import { OperationAdministrationPage } from "./OperationAdministrationPage";
import { SecurityPage } from "./SecurityPage";
import { SignInPage } from "./SignInPage";
import { StorageFolderAdministrationPage } from "./StorageFolderAdministrationPage";
import { TopologyAdministrationPage } from "./TopologyAdministrationPage";
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
    { component: CertificateAdministrationPage, path: "/admin/certificates" },
    { component: IdentityAdministrationPage, path: "/admin/identities" },
    { component: OperationAdministrationPage, path: "/admin/operations" },
    {
      component: StorageFolderAdministrationPage,
      path: "/admin/storage-folders",
    },
    { component: TopologyAdministrationPage, path: "/admin/topology" },
    { component: VolumeAdministrationPage, path: "/admin/volumes" },
    { component: NotFoundPage, path: "*404" },
  ],
});
