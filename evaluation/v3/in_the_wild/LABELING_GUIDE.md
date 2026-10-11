# Labeling guide: in-the-wild audit

For the two annotators. Authority: `CRITERIA.md` section 7, Amendment 1 (blind dossiers), Amendment 2 and its
clarification. If this page and `CRITERIA.md` disagree, `CRITERIA.md` wins.

**You get** one dossier per code (`L-001` ...): raw evidence from one 45-second sandbox run and from the package. It has no
score, no detector name and no flag; do not try to find out which samples were flagged, and do not discuss labels with the other
annotator until both sheets are submitted (deadline 2026-10-13; reconciliation 2026-10-14). **You fill** your own sheet
(`rater_1.csv` or `rater_2.csv`): `code, label, evidence, notes`. `evidence` = the dossier item (and the listing / policy sentence)
that decides the label. Tool outputs, VirusTotal verdicts and a later removal from the store are supporting evidence only.

## Five labels, in order of precedence

harmful > undisclosed-collection > grey > benign > undetermined. Give the first label whose definition fits.

1. **harmful**: a behaviour seen in the trace **and** confirmed in the code, **not disclosed** in the store listing or privacy
   policy, of one of these kinds: sending browsing history, cookies, passwords / session tokens or page content (forms,
   e-mail, messages) to anyone (a third party **or** the developer's own server); injecting code, affiliate links or ads;
   downloading and executing remote code; hijacking search or the new tab without disclosure.
   *Abstract example:* a script reads the page's form fields and posts them to a server unrelated to the page, and the policy says
   nothing about it.
2. **undisclosed-collection**: the **developer's own server** receives page URLs / titles, telemetry tied to a persistent
   identifier, or account identifiers (for example an e-mail address), and this is **not declared** in the store's privacy
   practices or in the privacy policy. (Cookies, credentials and page content are `harmful`, not this label.)
   *Abstract example:* every page change makes the extension send the page URL and a stored random ID to the developer's
   domain, and the listing declares no such data.
3. **grey**: data collection that **is disclosed** (listing or policy), or an analytics SDK.
   *Abstract example:* the extension sends usage events with an install ID to a well-known analytics service and the policy
   lists it.
4. **benign**: none of the behaviours above.
   *Abstract example:* the only traffic is to the developer's API with data the user typed for that feature, or no traffic.
5. **undetermined**: not enough evidence, for example the code is obfuscated and neither the code nor the listing settles
   whether the transfer is disclosed. Say what is missing in `notes`.

Rules of thumb: a request alone is not a label (look at what it carries and where it goes); an excerpt shows a code path, not
that it ran, so combine it with the request table; "disclosed" means stated in the Privacy practices section of the listing
or in the policy text, not only implied by the extension's purpose.

## How to look up the privacy practices on the Chrome Web Store

1. Open the listing link of the dossier. If the page says the item is unavailable, record `listing unavailable` in `notes` and
   judge disclosure from the policy link of the dossier (if any) alone.
2. On the listing, open the **Privacy** section (below the screenshots). It shows the developer's declarations: the data
   types the extension says it collects (for example *web history*, *website content*, *personally identifiable information*,
   *authentication information*, *user activity*) and three certifications (not sold to third parties; not used for unrelated
   purposes; not used for creditworthiness).
3. Follow the **privacy policy** link of the listing (also given in the dossier when found) and search the text for the data
   type you saw in the trace and for the recipient's domain.
4. Compare: what the trace shows leaving the browser vs. what is declared in 2 and 3. Quote the sentence (or write "not
   mentioned") in `evidence`.
