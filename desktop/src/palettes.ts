type Colors = readonly [
  surround: string,
  surface: string,
  text: string,
  muted: string,
  receive: string,
  send: string,
]

type Variant = readonly [label: string, colors: Colors]

// Upstream palettes adapted to dashboard surfaces and chart roles.
// Some accent and muted values are adjusted for contrast on those surfaces.
export const palettes = {
  // https://www.nordtheme.com/docs/colors-and-palettes/
  nord: {
    name: "Nord",
    light: [
      "Snow Storm",
      ["#e5e9f0", "#eceff4", "#2e3440", "#4c566a", "#3d617d", "#825470"],
    ],
    dark: [
      "Polar Night",
      ["#2e3440", "#3b4252", "#eceff4", "#d8dee9", "#88c0d0", "#cba7c4"],
    ],
  },
  // https://draculatheme.com/spec
  dracula: {
    name: "Dracula",
    light: [
      "Alucard",
      ["#efeddc", "#fffbeb", "#1f1f1f", "#5b574f", "#036a96", "#a3144d"],
    ],
    dark: [
      "Dracula Classic",
      ["#21222c", "#282a36", "#f8f8f2", "#bbc2df", "#8be9fd", "#ff79c6"],
    ],
  },
  // https://github.com/catppuccin/catppuccin
  catppuccin: {
    name: "Catppuccin",
    light: [
      "Latte",
      ["#e6e9ef", "#eff1f5", "#4c4f69", "#5c5f77", "#185bdc", "#8839ef"],
    ],
    dark: [
      "Mocha",
      ["#181825", "#1e1e2e", "#cdd6f4", "#a6adc8", "#89b4fa", "#cba6f7"],
    ],
  },
  // https://rosepinetheme.com/palette/
  rosepine: {
    name: "Rosé Pine",
    light: [
      "Dawn",
      ["#f2e9e1", "#faf4ed", "#575279", "#625d76", "#286983", "#785592"],
    ],
    dark: [
      "Main",
      ["#191724", "#1f1d2e", "#e0def4", "#aaa6c1", "#9ccfd8", "#ebbcba"],
    ],
  },
  // https://github.com/tokyo-night/tokyo-night-vscode-theme
  tokyonight: {
    name: "Tokyo Night",
    light: [
      "Day",
      ["#d5d6db", "#e1e2e7", "#343b58", "#515a79", "#2959aa", "#7146a0"],
    ],
    dark: [
      "Night",
      ["#16161e", "#1a1b26", "#c0caf5", "#a9b1d6", "#7aa2f7", "#bb9af7"],
    ],
  },
  // https://github.com/gruvbox-community/gruvbox
  gruvbox: {
    name: "Gruvbox",
    light: [
      "Light",
      ["#ebdbb2", "#fbf1c7", "#3c3836", "#665c54", "#376e4c", "#af3a03"],
    ],
    dark: [
      "Dark",
      ["#1d2021", "#282828", "#ebdbb2", "#bdae93", "#8ec07c", "#fe8019"],
    ],
  },
  // https://ethanschoonover.com/solarized/
  solarized: {
    name: "Solarized",
    light: [
      "Light",
      ["#eee8d5", "#fdf6e3", "#073642", "#526568", "#1769a8", "#a52162"],
    ],
    dark: [
      "Dark",
      ["#002b36", "#073642", "#eee8d5", "#a5b5b6", "#56b5eb", "#ec77ad"],
    ],
  },
  // https://github.com/sainnhe/everforest
  everforest: {
    name: "Everforest",
    light: [
      "Light",
      ["#efebd4", "#fdf6e3", "#3f4d4f", "#53605e", "#567021", "#9b475d"],
    ],
    dark: [
      "Dark",
      ["#272e33", "#2e383c", "#d3c6aa", "#a9b4a2", "#a7c080", "#d699b6"],
    ],
  },
  // https://github.com/rebelot/kanagawa.nvim
  kanagawa: {
    name: "Kanagawa",
    light: [
      "Lotus",
      ["#e7dba0", "#f2ecbc", "#545464", "#5f5e6c", "#3e6c62", "#8f435c"],
    ],
    dark: [
      "Wave",
      ["#16161d", "#1f1f28", "#dcd7ba", "#a6a69c", "#7e9cd8", "#d27e99"],
    ],
  },
  // https://github.com/primer/primitives
  github: {
    name: "GitHub",
    light: [
      "Light",
      ["#f6f8fa", "#ffffff", "#1f2328", "#59636e", "#0969da", "#8250df"],
    ],
    dark: [
      "Dark",
      ["#0d1117", "#151b23", "#e6edf3", "#9198a1", "#58a6ff", "#bc8cff"],
    ],
  },
} as const satisfies Record<
  string,
  { name: string; light: Variant; dark: Variant }
>

export type Palette = keyof typeof palettes
export const defaultPalette: Palette = "nord"

export function applyPalette(root: HTMLElement, id: Palette, dark: boolean) {
  const [, [surround, surface, text, muted, receive, send]] =
    palettes[id][dark ? "dark" : "light"]
  root.classList.toggle("dark", dark)
  root.dataset.palette = id
  root.style.setProperty("--surround", surround)
  root.style.setProperty("--plate", surface)
  root.style.setProperty("--ink", text)
  root.style.setProperty("--quiet", muted)
  root.style.setProperty("--dw-accent", receive)
  root.style.setProperty("--purple", send)
}
