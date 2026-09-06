// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";
import { CertificateProvisioningForm } from "./CertificateProvisioningForm";
import { CertificateStatusCard } from "./CertificateStatusCard";
import { ManualDnsTaskList } from "./ManualDnsTaskList";
import { MeshLocalCertificateForm } from "./MeshLocalCertificateForm";
import {
  createManualDnsTaskDirectory,
  createCertificateStatusResource,
  type CertificateAdministrationClient,
} from "./model";

export function CertificateAdministrationPanel(
  props: Readonly<{
    client: CertificateAdministrationClient;
    csrfToken: string;
  }>,
): JSX.Element {
  const directory = createManualDnsTaskDirectory(() => props.client);
  const status = createCertificateStatusResource(() => props.client);
  void directory.loadInitial();
  void status.load();

  return (
    <div class="certificate-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / HTTPS</p>
        <h1>Certificates</h1>
        <p>
          MeshSpan obtains, renews and distributes one public identity across
          eligible gateways. Use manual DNS only when automation is unavailable.
        </p>
      </header>
      <AdministrationNavigation current="certificates" />
      <CertificateStatusCard resource={status} />
      <MeshLocalCertificateForm
        client={props.client}
        csrfToken={props.csrfToken}
      />
      <CertificateProvisioningForm
        client={props.client}
        csrfToken={props.csrfToken}
        refreshTasks={directory.loadInitial}
      />
      <ManualDnsTaskList directory={directory} />
    </div>
  );
}
