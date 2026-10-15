# SecurCode Console Design

## Visual Direction

SecurCode uses a restrained near-black editorial operations-console language for security engineers. The interface is dense where evidence matters, quiet where the operator is deciding, and avoids decorative dashboard treatment.

## Color Roles

- `#0b0d0f` is the near-black page canvas; `#111518` and `#151a1e` establish working surfaces.
- `#ebece9` is the off-white primary text and `#9ca4a9` is reserved for secondary information.
- `#86accb` is reserved for primary actions, selected navigation, focus, and links.
- Red, amber, and green are semantic-only roles for severity and system state.
- Neutral borders use `#2a3035` and `#1e2428` to keep table structure visible without heavy elevation.

## Typography

The web platform sans stack keeps controls familiar and compact. Headings use modest weight and scale rather than display styling. Numeric metrics use tabular numerals for quick comparison; paths and rule IDs use monospace only where they represent code or measured identifiers.

## Layout And Components

The shell is a charcoal top bar, a slightly lighter charcoal left navigation rail, and a near-black content canvas with an editorial alignment system. Content sections use one-pixel rules instead of nested cards or shadows. Tables are the primary evidence surface. The scan form is an inline action section, so launching a scan does not require a modal or route change.

## States And Responsive Behavior

Loading uses restrained skeleton bars. Empty results explain the next action. API and scan errors remain inline and name recovery steps. On narrow screens, the sidebar becomes a compact menu, metrics stack vertically, and tables retain a horizontal scroll region so data is not truncated.
