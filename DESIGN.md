# Signal Watch: design

Rules for the interface in `public/index.html`. `ARCHITECTURE.md` covers the system. Change this file in the same pull request as the interface.

## 1. The user and the job

One security owner in a 3 to 8 person NZ public-sector IT team has 30 minutes a day. The interface must answer, in this order:

1. Is the data current? (header: last sync, failures, next sync)
2. What needs action now? (Today: Act tile and queue)
3. Why is it at this level, and what do I do? (drawer: rule, sources, fix)
4. Am I finished? (empty queue: "No open Act signals", or "All clear" with no level selected)

A change that makes one of these slower to answer needs a stated reason.

## 2. Principles

| Principle | Test |
| --- | --- |
| A number has a unit or a label | Cover the rest of the screen: can you still say what the number counts? |
| A time has a subject | "Last sync 22:04", never "Last 22:04". Add the weekday or date when it is not today |
| Missing is not zero | Show "never", "Off" or "None". Show 0 only for a measured 0 |
| Stale data is visible | A sync older than 26 hours shows "Overdue" |
| A problem links to its fix | "2 sources failed" opens Sources |
| Color is never the only signal | Each level has an icon and a word as well as a color |
| Identity is not cut off | Product names, IDs and titles wrap, or give the full text on hover. Secondary text is shortened first |
| Every triage action has a key | `J` `K` `Enter` `A` `N` `T` `U`, and the button shows the key |

## 3. Header status

| State | Text | Dot |
| --- | --- | --- |
| Synced today | Last sync **22:04** · Next sync **Thu 07:30** | accent |
| Window 1320 px or wider, Live | adds "6 min ago" | accent |
| Within 6 days | Last sync **Mon 07:30** | accent |
| Older | Last sync **12 Nov 07:30** | accent or Plan |
| Older than 26 hours, Live, schedule on | adds the "Overdue" chip | Plan |
| Some sources failed | adds "2 sources failed", which opens Sources | Act (over Plan when also overdue) |
| No run yet | Last sync **never** | muted |

- "Sync" in the header is the source run. Incident and ticket sync is "Last two-way sync" in Settings. Do not shorten either one.
- "Last sync" is visible at every width. Below 980 px "Next sync" is dropped, a failure reads "2 failed", and a failure replaces the Overdue chip. Below 560 px the label sits above the time, the Search and Run now labels, the Shortcuts button and the Overdue chip are dropped, and a failure shows as an icon and a count. The time keeps its weekday or date, so old data still shows as old.
- The age and the clock update every 30 seconds. They are not in a live region, so a screen reader does not repeat them. Run results are announced by toasts.
- Code: `syncStatus()` in `public/index.html`.

## 4. Color

Every value is `light-dark(light, dark)`. Contrast is the lowest ratio measured on the page and card surfaces in both themes (WCAG 2 AA: 4.5 for text, 3.0 for control edges).

| Role | Light | Dark | Lowest contrast |
| --- | --- | --- | --- |
| Page | `#eef1f5` | `#111418` | |
| Card | `#fbfcfd` | `#171b21` | |
| Text | `#111418` | `#e9e9ed` | 14.3 |
| Text, second level | `#343a44` | `#cdd3dc` | 10.1 |
| Text, muted | `#555d6b` | `#8d95a3` | 5.7 |
| Text, muted, 11 to 12 px | `#555d6b` | `#aab2bf` | 5.9 |
| Accent (focus, selection, primary edge) | `#2563a8` | `#5aa0e6` | 5.4 |
| Link and text action | `#1d4f86` | `#b9d6f5` | 7.4 |
| Control edge that carries meaning | `#858d9b` | `#6f7785` | 3.0 |

Level colors are defined once, in `lvStyle()`: Act red, Plan amber, Watch blue, Info grey. Use them only for levels and for status of the same severity (failure: Act, overdue: Plan).

## 5. Type

Inter 400 and 500. IDs use the system monospace stack.

| Size | Use |
| --- | --- |
| 30 | Tile count |
| 25 | Page title |
| 17 to 22 | Drawer title, chart figure |
| 14 | Body, row title |
| 13 | Controls, card title |
| 12 | Metadata, secondary controls |
| 11 | Chips, chart labels, uppercase captions. Nothing new below 11 |

- Numbers that update or line up use `font-variant-numeric: tabular-nums`.
- Headings use `text-wrap: balance`, row titles `text-wrap: pretty` with a two-line limit.
- Uppercase with `.08em` tracking is for captions only.

## 6. Space, shape, depth

- Spacing steps: 2, 4, 6, 8, 10, 12, 14, 18. Page gutter 28, phone 14.
- Radius: card 14, control 8, chip and nested control 6, key cap 4. A nested radius is smaller than its parent's.
- Cards use a 1 px `box-shadow` ring. Borders are for controls and dividers.
- Control height: header and paging 36, form and toolbar 30 to 34, row action 26, chip 20 to 24. Target: nothing clickable is smaller than 24 × 24 (WCAG 2.5.8).

## 7. Layout

| Width | Layout |
| --- | --- |
| 1320 and up | Drawer sits beside the page, sync age shown |
| 980 to 1319 | Sidebar 232, drawer overlays the page |
| 560 to 979 | Sidebar 64 |
| Below 560 | Sidebar 64, tiles in two columns (one at 320), queue row stacked: level, title, act-by date, metadata |

The Today list and charts change from two columns to one by `auto-fit` and have no breakpoint. Height is `100dvh`, so a phone browser's toolbars do not cover the last row. There is no horizontal page scroll down to 320 px.

## 8. Motion

- 120 to 220 ms for state changes, 300 ms for bars. Transitions name their properties, never `all`.
- Press: `scale(.96)` on tiles and Run now. No animation on load.
- `prefers-reduced-motion` turns off all transitions.
- The saved theme is applied in `public/boot.js` before first paint.

## 9. Words

- Labels are one or two words, sentence case, no full stop.
- Use the same word for the same thing everywhere: signal, item, source, level, sync, run.
- Ages read "5 d ago". Deadlines read "Overdue 5 d" or "Act-by 5 d".
- Charts state their window and scale: "14 days", "Today · log scale", "All runs".
- A toast is an outcome plus an object: "Acknowledge · SW-6010".

## 10. Accessibility

- `lang="en-NZ"`, a skip link, one `h1` per page, and a visible 2 px focus ring.
- Lists are `listbox` with one tab stop. The drawer returns focus to its row.
- An icon-only button has an `aria-label` and a `title`. A tile's label says the whole sentence: "Act: 8 open, 8 total".

## 11. Check before merge

1. Screenshots at 1440, 1000, 700, 390 and 320 px, dark and light at 1440.
2. Header states: normal, failed sources, overdue, failed and overdue, never synced. Include 560 px.
3. `document.documentElement.scrollWidth <= innerWidth`, and no clipped header text.
4. Keyboard only: reach, decide, undo.
5. No console errors, and `npm test` passes.

## 12. Known gaps

| Gap | Effect | Proposed fix |
| --- | --- | --- |
| Row actions are 26 px, some icon buttons 26 to 28 px | Small for touch | 40 px targets under `pointer: coarse` |
| "New signals" uses one linear scale | A bulk import day flattens the other days | Limit the scale and label the cut bar |
| Every row repeats the level chip when one level is selected | Takes 82 px from the title | Hide the chip column in that case |
| 10.5, 11.5 and 12.5 px text remains in Settings and IDs | Off the scale | Move to 11, 12 and 13 |
| Colors are repeated inline | A palette change edits many lines | CSS custom properties |
