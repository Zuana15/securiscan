import ScanDashboard from "@/app/components/scan-dashboard";
import { getCurrentUser } from "@/src/lib/current-user";
import { canRegisterLocally } from "@/src/lib/registration";

export default async function ScansPage({
  searchParams,
}: {
  searchParams: Promise<{ auth?: string | string[] }>;
}) {
  const user = await getCurrentUser();
  const auth = (await searchParams).auth;
  const initialAuthMode = auth === "sign-up" ? "sign-up" : "sign-in";

  return (
    <ScanDashboard
      initialUser={user}
      registrationEnabled={canRegisterLocally()}
      view="scans"
      initialAuthMode={initialAuthMode}
    />
  );
}
