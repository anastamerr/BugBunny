Here is the full, final prompt optimized for **Vite + React + Tailwind v4**.

-----

**ROLE:**
You are a Senior UI/UX Engineer specialized in **Tailwind CSS v4** and Modern React patterns.

**TASK:**
Completely refactor the current frontend design to match the "Neon Wave" aesthetic derived from the attached reference image. We are moving to a High-Contrast "OLED" Dark Mode.

**VISUAL ANALYSIS:**

  * **Palette:** "Void" Black background (for true OLED contrast) + "Neon Mint" Green accents.
  * **Geometry:** Exaggerated rounded corners (Squircles/Pills) and thick, mono-weight lines.
  * **Vibe:** Minimalist, high-energy, fluid.

**TECHNICAL IMPLEMENTATION (Tailwind v4 Strict Mode):**

**1. CSS Configuration (`src/index.css`):**
Replace the current CSS setup. Do NOT use `tailwind.config.js`. Use the **v4 CSS-first configuration** with the `@theme` directive. Implement these exact tokens:

```css
@import "tailwindcss";

@theme {
  /* Color Palette */
  --color-neon-mint: #00d768ff;  /* Vivid Green from image */
  --color-void: #000000;       /* True Black */
  --color-surface: #111111;    /* Slightly lighter black for heavy grouping only */

  /* Geometry & Typography */
  --radius-card: 24px;         /* Large rounded corners */
  --radius-pill: 9999px;       /* Full pill shape */
  --font-sans: "Inter", system-ui, sans-serif;
  --ease-fluid: cubic-bezier(0.25, 0.46, 0.45, 0.94);
}
```

**2. Component Rules:**
Refactor `App.jsx`, Layouts, and Components to use these new utility classes:

  * **Global Reset:** Force `body` to `bg-void text-white font-sans antialiased selection:bg-neon-mint selection:text-void`.
  * **Buttons (Primary):** `bg-neon-mint text-void font-bold tracking-tight rounded-pill hover:scale-105 active:scale-95 transition-transform duration-200 ease-fluid`.
  * **Cards/Containers:** `bg-void border border-white/10 rounded-card hover:border-neon-mint/50 transition-colors`.
  * **Inputs:** `bg-void border-2 border-white/10 text-white rounded-pill focus:border-neon-mint focus:outline-none placeholder-white/30`.
  * **Typography:** Use pure White (`text-white`) for headings. Use `text-white/60` for secondary text. Never use gray hex codes, use opacity modifiers.

**EXECUTION STEPS:**

1.  Overwrite `src/index.css` with the v4 theme setup above.
2.  Rewrite the Main Layout/App component to apply the `bg-void` canvas.
3.  Refactor the Navigation and Hero sections to use the `neon-mint` accent color and `rounded-pill` geometry.

**GOAL:**
The final output must look identical to the reference vibe: Pitch black, glowing green, and very round. Start coding.



///////////////////

Breakthrough features implemented

- Bug workflow editing (status/team/notes) via PATCH /api/bugs/:id (frontend/src/pages/BugDetail.tsx, backend/src/api/routes/bugs.py)
- Bug detail view with GitHub link, duplicates, and comment context
- Live bug queue updates via Socket.IO (/ws)

Validated

- Backend tests: cd backend; pytest
- Frontend: cd frontend; npm run lint && npm run build
