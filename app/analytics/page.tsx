import ScanDashboard from "@/app/components/scan-dashboard";
import { getCurrentUser } from "@/src/lib/current-user";
import { canRegisterLocally } from "@/src/lib/registration";

export default async function AnalyticsPage() {
  const user = await getCurrentUser();
  return <ScanDashboard initialUser={user} registrationEnabled={canRegisterLocally()} view="analytics" />;
}
