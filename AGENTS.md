# Working instructions for Penumbra

## Start here

Read [`docs/handoff.md`](docs/handoff.md) for the current commit, rebuild and
publish commands, the temporary tunnel, GitHub upload, custom-domain setup, and
the open decisions. Read [`docs/evaluation.md`](docs/evaluation.md) before making
any claim about detection efficacy.

## Website workflow - required

> Before you design anything, do the Pinterest research. Open the board and the
> individual pins, read the captions, follow the creators' source links, watch
> the video pins and extract frames. Search adjacent terms for the style, type,
> color, texture, grid, motion, and interface. Write an evidence table of what
> each reference teaches about attention, structure, typography, color, grid,
> texture, surface, motion, icons, and accents. Then choose one specific
> direction for this product, list the three moves that prove it, and list what
> you will not do. Only after that, write the code. If a source is login-walled,
> say so and use the public pin page or the creator's live site instead.

Before building or redesigning a website:

1. Load `frontend-design-pro` and its `design-research` / `web-interface`
   catalog skill.
2. Load `pinterest-reference-first`.
3. Collect 3–5 current references from Pinterest or Reddit, then check the
   prompt references below for structure and constraints.
4. Extract typed values (palette, type, grid, easing, spacing). Write the
   evidence table and one direction before touching code.
5. Run the rendered audit after building: 390 / 768 / 1440, Corona and Umbra,
   console, keyboard, contrast, Lighthouse.

Reference prompts and what they contribute:

- [TISA: 40+ best prompts for AI website design](https://www.tisatech.in/blog/best-prompts-for-website-design/)
  — the six-part brief: what, who, sections, style, colors/fonts, features.
  Also mobile-first, 44px touch targets, and 320–1440 testing.
- [AdvertisingBusiness: 25 AI prompts for website design](https://www.advertisingbusiness.org/ai-prompts-for-website-design/)
  — the master context block, one primary CTA plus at most two secondary
  actions, compare three directions, and an accessibility/conversion QA pass.
- [AI UX Playground: prompts for designers](https://aiuxplayground.com/prompts/for-designers)
  — design briefs, information architecture, visual hierarchy, design tokens,
  “add taste”, “polish UI”, “grill my design”, and AGENTS/DESIGN.md prompts.

Do not copy a reference. Extract the rule, translate it into this product's
tokens, and name the source behind the decision.

## Pinterest first

Before any visual, UI, brand, motion, or layout change:

1. Load the `pinterest-reference-first` skill.
2. Read [`docs/design.md`](docs/design.md).
3. If the change is a new direction, reopen the relevant pins, captions, source
   links, and video frames. Do not design from memory.
4. Write the observed → decision → trade-off trail in the research file.

The full skill and the Desktop brief are at:

- `~/.agents/skills/pinterest-reference-first/SKILL.md`
- `~/Desktop/Pinterest-First-Design-Instruction.md` (if present)

## The system

- Palette: Paper `#F6F4F1`, Stone `#E4DED2`, Coral `#F95C4B` (fills) /
  `#C9402C` (text), Black `#141210`, Sunset `#EA6113` → `#F88F22` → `#FBB931`
  → `#FFE3B3`.
- Type: Fraunces for the editorial voice, Manrope 800 for one poster word,
  JetBrains Mono for data. Do not add a fourth family without a reason.
- Themes: **Corona** is the light record; **Umbra** is the dark instrument.
- One poster move per page. The cover carries the black totality plate, the
  corona disc, and the paper ticket. Everything else stays readable.
- Geometry: the page is an eclipse instrument. The sky ring, cut-corner plates,
  capsule controls, eclipse nodes, bead rails, contact ribbon, and path of
  totality are part of the system, not decoration.
- The contact ribbon is interactive: each phase pins its nearest hour on the
  chart. Keep the buttons and their labels.
- Texture goes on surfaces, never behind body copy.
- Motion is an instrument. Respect `prefers-reduced-motion` and keep the final
  state.

## Source of truth

- [`dashboard/styles.css`](dashboard/styles.css)
- [`dashboard/template.html`](dashboard/template.html)
- [`dashboard/app.js`](dashboard/app.js)
- [`pipeline/report.py`](pipeline/report.py)
- [`docs/design.md`](docs/design.md)
- [`docs/evaluation.md`](docs/evaluation.md)

## Before calling it done

```powershell
node --check dashboard\app.js
.\.venv\Scripts\python.exe -m pipeline.report
.\.venv\Scripts\python.exe -m pipeline.publish
.\.venv\Scripts\python.exe -m pipeline.heatmap
.\.venv\Scripts\python.exe -m pipeline.lint
.\.venv\Scripts\python.exe -m pipeline.compile --check
.\.venv\Scripts\python.exe -m pipeline.coverage --check
.\.venv\Scripts\python.exe -m pytest -q
```

Then check the built page at 1440 and at a true 390px iframe, in light and dark,
with no console errors and Lighthouse accessibility / best practices / SEO at
100. Refresh `docs/assets/dashboard-corona.png` and `docs/assets/dashboard-umbra.png`.
