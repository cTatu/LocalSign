# LocalSign Brand Sheet

Concept: **The Private Seal** — a notary shield with a bronze check. Legal weight,
browser-tab privacy. (Synthesized from three subagent explorations; unanimous
rules: no clouds, upload arrows, padlocks-as-travel, globes, or script fonts.)

## Palette

| Role       | Hex       | Used for                              | Contrast                          |
|------------|-----------|---------------------------------------|-----------------------------------|
| Navy       | `#1E3A8A` | Primary: buttons, app icon bg, links  | White on navy 10.2:1 (AAA)        |
| Bronze     | `#B45309` | Check on light surfaces, focus rings  | White on bronze 5.0:1 (AA)        |
| Amber      | `#F5B544` | Check on navy surfaces (icon/favicon) | Decorative on navy                |
| Ink        | `#0F172A` | Body text                             | On white 17.1:1, on mist 14.5:1   |
| Paper      | `#FFFFFF` | Page background                        | —                                 |
| Mist       | `#F1F5F9` | Cards, status wells                   | Ink on mist 14.5:1                |
| Sealed Green | `#047857` | Signed/valid states only            | White on green 5.1:1 (AA)         |

## Typography (system only, no webfonts — zero network)

- UI/headings: `ui-rounded, "SF Pro Rounded", system-ui, -apple-system, "Segoe UI", sans-serif`
- Proof/data (hashes, cert details, timestamps): `ui-monospace, "SF Mono", Menlo, Consolas, monospace`

## Assets

- `assets/mark.svg` — shield + bronze check, stroke mark for headers (32×32 grid)
- `assets/logo.svg` — horizontal lockup (mark + wordmark) for README/social
- `assets/favicon.svg` — white shield + amber check on navy rounded square
- `assets/icon.svg` — 512px app icon, 22% corner radius, same composition

## Rules

1. The check is always bronze-on-light or amber-on-navy — never navy-on-navy.
2. Green appears only for verified/signed states, never decoration.
3. Nothing in the artwork may imply files travel: no clouds, arrows, globes.
4. Favicon keeps the solid rounded-square form below 32px; stroke mark at 32px+.
