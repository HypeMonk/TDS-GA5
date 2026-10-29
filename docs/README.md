# GA3 Made Simple

A static student guide for Q1–Q8. It does not submit answers, call the solver, collect account/API tokens, or require a database.

## Files

- `src/guide.html`: editable, self-contained guide source and the private-preview page.
- `index.html`: generated standalone page for GitHub Pages or any static host.
- `build.py`: wraps the source in a standard HTML document.

After editing the source, build from the repository root:

```powershell
python -I -B docs/build.py
```

For a local preview:

```powershell
python -I -B -m http.server 8080 --bind 127.0.0.1 --directory docs
```

Open `http://127.0.0.1:8080/`. Stop the server when done.

## GitHub Pages

After the guide has been committed and pushed, enable **Repository Settings → Pages → Deploy from a branch**, select the branch containing the guide, and choose **`/docs`**. This is separate from the Render backend.

The page has no third-party runtime dependencies. Navigation uses question hashes; the optional colour-theme preference is stored only in that viewer's browser. Copy buttons fall back to selecting text when clipboard access is unavailable.

## Content boundaries

- Q1–Q4 Check/Save limits come from the published exam script.
- Q5's short bonus note summarizes the professor's email announced to all students. Published game dates are shown, including closed drawing/guessing windows.
- Q6 opens on a recommended Pro/download-tool tab, with a separate simplest/free tab. The selector supports click and keyboard navigation. Pro preference is based on the guide owner's reported quality test. The reported MeshyGrab allowance is two downloads. Model access, credits, extension limits, and export rights remain account-dependent; the guide does not provide a paid-export bypass.
- Q6 accepts at most 2,000,000 bytes. Q7 must be strictly below 100,000 bytes. A format/access pass is not a likeness or quality guarantee.
- Hard refresh is a portal-UI tip, not a reset of attempts or a guarantee against changing audit scores.
- GT Indian's backup solver is linked as a website; its homepage is not presented as a verified question-specific API endpoint.
- Q6/Q7 file hosting uses public GitHub uploads and commit-pinned jsDelivr CDN URLs to avoid stale mutable-branch links.
- Coloured callouts keep their meaningful body text without visible category labels or a colour legend.

The existing Python solver files are not changed by this guide.
