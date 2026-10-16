# Synthetic fixtures
These log templates are **synthetic**. They were written for unit tests from the documented CMTrace record format and the IME step messages in Microsoft's support tip ("Understanding the flow behind deployment, delivery, and processing of a Win32 application through Intune", checked Oct 16, 2026), plus the "without mapping" and GRSManager wording quoted by Liviu Barbat (patchtuesday.com, 2022) and Rudy Ooms (call4cloud.nl, 2022). They are not real device logs. App IDs and names are placeholders.

The tests copy each `*.template` file to a temporary folder and replace `{D1}` with yesterday's date and `{DOLD}` with a date 400 days back, so the tests do not expire.
