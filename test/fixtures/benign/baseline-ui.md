---
name: baseline-ui
description: Remove agent UI slop. Improve spacing, typography, and states.
---

# Baseline UI

When reviewing or generating UI code, apply these constraints to avoid generic
"AI-generated" aesthetics.

## Spacing
- Use a consistent spacing scale (4px base). Avoid arbitrary values.
- Group related elements; separate unrelated ones with deliberate whitespace.

## Typography
- Limit to two font families. Establish a clear type scale.
- Body text 16px minimum. Line height 1.5 for paragraphs.

## States
- Every interactive element needs hover, focus, active, and disabled states.
- Focus rings must be visible for keyboard users.

## Motion
- Respect prefers-reduced-motion. Keep transitions under 200ms for UI feedback.

Review the file the user provides and suggest concrete diffs.
