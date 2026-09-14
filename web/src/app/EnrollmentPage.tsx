// SPDX-License-Identifier: GPL-2.0-only

import { useNavigate } from "@solidjs/router";
import type { JSX } from "@solidjs/web";

import { EnrollmentForm } from "../features/user-enrollment/EnrollmentForm";
import { useSession } from "./session";

export function EnrollmentPage(): JSX.Element {
  const session = useSession();
  const navigate = useNavigate();
  const signIn = async (key: string): Promise<void> => {
    await session.signInWithApiKey(key, false);
    navigate("/", { replace: true });
  };
  return <EnrollmentForm client={session.client} signIn={signIn} />;
}
