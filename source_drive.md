Overview

This challenge focused on analyzing a seemingly normal frontend web application. The description hinted that extra information may have been unintentionally exposed within frontend assets, suggesting a client-side information disclosure vulnerability.

Approach

1. Inspecting the Website

Opened the provided web application and explored the UI.

Observations:

Clean marketing-style interface

No visible input fields or obvious vulnerabilities

Likely a static frontend-heavy application

This indicated:

The flag is probably not accessible through interaction, but through inspection.

2. Viewing Page Source

Checked the HTML source:

Right-click → View Page Source

Looked for:

Comments

Hidden strings

Inline scripts

No direct flag found.

3. Exploring Developer Tools

Opened DevTools → Sources tab

Key idea:

Modern web apps often load logic and data through JavaScript bundles.

4. Analyzing JavaScript Files

Navigated through loaded JS files:

main.js

app.js

Other bundled/minified scripts

Steps taken:

Pretty-printed minified files

Searched using keywords:

flag
secret
token
key

Examined hardcoded strings and variables

5. Identifying Exposed Data

Found within the JavaScript:

A hardcoded string resembling the flag format
or

A configuration object containing sensitive data

This confirmed:

Developers accidentally left internal/debug data in frontend assets.

6. Extracting the Flag

The flag was directly readable from the JavaScript source after inspection.

Key Insight

This challenge relied on:

Client-side leakage of sensitive data

Developers including internal/test values in production builds

Important principle:

Anything shipped to the browser is public — security must never rely on hiding data in frontend code.

Conclusion

By:

Inspecting frontend assets

Analyzing JavaScript bundles

Searching for hidden or hardcoded values

the flag was discovered without needing exploitation.
