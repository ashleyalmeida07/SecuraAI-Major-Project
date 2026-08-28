# Enhanced Reconnaissance Data

The reconnaissance flow and UI have been heavily upgraded to capture and display much deeper insights about the target attack surface!

## What changed
1. **AI Classifier Fallbacks**: 
   - We no longer rely purely on the AI to classify endpoints. If the AI hallucinates or fails, a deterministic regex-based fallback rule engine steps in.
   - For example: `/api/*` will always map to `API`, `.js` / `.css` will map to `Static Asset`, and `/admin` will map to `Dashboard`. This completely eliminates empty "unknown" rows in most situations.
2. **Form and Parameter Extraction**: 
   - The crawler now parses HTML for forms and extracts the actual `name` / `id` of `<input>`, `<select>`, and `<textarea>` elements. 
   - It also automatically extracts query parameters (e.g. `?id=123`). Both forms and query params are shown under the "Details" column in the table.
3. **Response Metadata**: 
   - We are now tracking response times (in seconds) and response sizes (converted to KB) to make this feel like a true performance/security scanner.
4. **Technology Fingerprinting**:
   - The crawler actively inspects `Server` and `X-Powered-By` HTTP response headers. It aggregates this data and displays the underlying technology (e.g. `nginx`, `Express`) in a new "Tech / Size" column.
5. **Interesting Paths Highlighting**: 
   - Quick wins like `/robots.txt`, `/sitemap.xml`, `.env`, and `/admin` are now actively flagged by the crawler and are highlighted with a glowing yellow `Flagged` badge right next to the URL in the report table.

## How to test it
1. Start a new scan on the **Scanner** page (Try a complex site that has forms and query parameters).
2. Once the scan is complete, click **View Report**.
3. In the Attack Surface Map table, observe the new `Tech / Size` and `Details` columns. 
4. Look out for the orange `Inputs: ...` badges marking forms, blue parameter badges, and yellow `Flagged` badges next to sensitive paths!
