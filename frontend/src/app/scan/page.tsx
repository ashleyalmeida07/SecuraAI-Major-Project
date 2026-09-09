import { redirect } from "next/navigation";

/**
 * The scan flows now each live on their own tab under /scan/<slug>. The old
 * single-page radio-group selector is gone; /scan lands on the static tab.
 */
export default function ScanIndexPage() {
  redirect("/scan/static");
}
