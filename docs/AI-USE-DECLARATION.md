# AI Use Declaration

**Project:** Mini-SIEM — A Web-Based Security Event Monitoring and Threat Detection System
**Project ID:** FYCP/2K26/109
**Institute:** Institute of Mathematics & Computer Science, University of Sindh, Jamshoro
**Supervisor:** Dr. Asadullah Burdi

Deliverable D-11.

---

## Important — read before completing

This declaration must be **accurate**. Under-declaring the use of AI
assistance is a form of academic misconduct at most institutions, and it is
usually detectable: examiners ask about design decisions in the viva, and a
student who cannot explain why their own code works as it does gives
themselves away far more clearly than a declaration ever would.

The template below is deliberately structured so an honest answer is easy to
give. **Fill it in truthfully, confirm it with Dr. Burdi, and check it
against your department's current policy** — institutional rules on AI use in
final year projects vary and change, and this document cannot substitute for
that policy.

The one thing that protects you in a viva is genuine understanding of the
system. Whatever the declaration says, make sure all three of you can explain
every module, every detection rule, and every design trade-off in your own
words. Section 4 below is provided to help you check that.

---

## 1. Declaration

We, the undersigned, declare that the use of artificial intelligence tools in
the preparation of this Final Year Project was as recorded below, and that
this record is complete and accurate to the best of our knowledge.

| Member | Roll No. | Signature | Date |
|---|---|---|---|
| Yasir Parveez | 2K23/CSM/146 | ________________ | __________ |
| Abdul Fatah | 2K23/CSM/03 | ________________ | __________ |
| Mushahid Hussain | 2K23/CSM/100 | ________________ | __________ |

---

## 2. Tools used

List every AI tool used at any stage.

| Tool | Version / model | Period used | Used by |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

---

## 3. Nature and extent of use

For each area, tick the level that honestly applies and describe the use.
Be specific — "assisted with code" is not a useful disclosure.

**Levels:**
- **(a) None** — no AI involvement
- **(b) Guidance** — asked conceptual questions; wrote the work ourselves
- **(c) Review** — wrote it ourselves, then asked AI to review or debug
- **(d) Co-authored** — AI produced substantial content that we reviewed, tested and modified
- **(e) Generated** — AI produced the content largely as submitted

| Project area | Level | Description of use |
|---|---|---|
| Proposal writing | ☐a ☐b ☐c ☐d ☐e | |
| Requirement analysis | ☐a ☐b ☐c ☐d ☐e | |
| System architecture / design | ☐a ☐b ☐c ☐d ☐e | |
| Database schema | ☐a ☐b ☐c ☐d ☐e | |
| Authentication module | ☐a ☐b ☐c ☐d ☐e | |
| Host management module | ☐a ☐b ☐c ☐d ☐e | |
| Threat intelligence registry | ☐a ☐b ☐c ☐d ☐e | |
| Log collection (SSH / Windows) | ☐a ☐b ☐c ☐d ☐e | |
| Log parsers | ☐a ☐b ☐c ☐d ☐e | |
| **Detection rule engine (R-01 … R-04)** | ☐a ☐b ☐c ☐d ☐e | |
| Dashboard and charts | ☐a ☐b ☐c ☐d ☐e | |
| Front-end JavaScript | ☐a ☐b ☐c ☐d ☐e | |
| Automated test suite | ☐a ☐b ☐c ☐d ☐e | |
| Security hardening | ☐a ☐b ☐c ☐d ☐e | |
| Sample / synthetic log data | ☐a ☐b ☐c ☐d ☐e | |
| Installation guide | ☐a ☐b ☐c ☐d ☐e | |
| User manual | ☐a ☐b ☐c ☐d ☐e | |
| Testing report | ☐a ☐b ☐c ☐d ☐e | |
| FYP-I report | ☐a ☐b ☐c ☐d ☐e | |
| FYP-II final report | ☐a ☐b ☐c ☐d ☐e | |
| Presentation slides | ☐a ☐b ☐c ☐d ☐e | |
| Poster | ☐a ☐b ☐c ☐d ☐e | |

---

## 4. Verification of understanding

Confirm that every group member can explain the following **without
assistance**. If any box cannot honestly be ticked, study that area before
the viva — this is the section that actually determines how the viva goes.

- ☐ Why events and alerts are stored in separate database tables, and what
  capability would be lost if they were combined
- ☐ Why rule R-01 uses a threshold within a sliding time window rather than
  alerting on every failed login, and what happens with 4 failures, or with 6
  failures spread over 6 hours
- ☐ How the system prevents duplicate alerts when detection is re-run
- ☐ Why the normalised event format means the detection rules do not know
  which log source an event came from
- ☐ Why marking an address as `BANNED` and re-running detection changes the
  severity of evidence already collected
- ☐ Why `Failed password for invalid user bob` is classified as
  `INVALID_USER` rather than `FAILED_LOGIN`, and how pattern ordering
  achieves that
- ☐ What CSRF protection is, and why exempting the JSON API from it was a
  vulnerability
- ☐ Why raw log batches are archived to Parquet before analysis, and why
  clearing the database does not delete them
- ☐ What each of the 95 tests is verifying, in general terms, and why the
  negative test cases matter more than the positive ones
- ☐ The limitations of the system and what you would build next

**Confirmed by:**

Yasir Parveez ________________  Abdul Fatah ________________  Mushahid Hussain ________________

---

## 5. Statement of original contribution

Describe, in your own words, what the team contributed independently of any
AI assistance — the decisions you made, the problems you diagnosed, the
direction you set, and the work you rejected or redirected.

_______________________________________________________________________

_______________________________________________________________________

_______________________________________________________________________

_______________________________________________________________________

_______________________________________________________________________

---

## 6. Verification and testing

We confirm that:

- ☐ All code in the repository has been read and understood by the team
- ☐ The system has been run and tested by the team on their own machines
- ☐ The 95 automated tests were executed and observed to pass
- ☐ The demonstration workflow was rehearsed end to end
- ☐ All figures quoted in the reports were reproduced and verified
- ☐ No code, text or data was submitted without review
- ☐ All third-party libraries are used in accordance with their licences and
  acknowledged in the reports

---

## 7. Similarity report

| Item | Detail |
|---|---|
| Tool used | ____________________ |
| Date of check | ____________________ |
| Similarity index | ____________________ |
| Report attached | ☐ Yes ☐ No |

---

## 8. Supervisor acknowledgement

I confirm that the AI use declared above was discussed with me and is
consistent with departmental policy.

Supervisor: Dr. Asadullah Burdi

Signature: ____________________  Date: ______________

**Remarks:**

_______________________________________________________________________

_______________________________________________________________________
