/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper: "#E8EDF2",
        panel: "#F8FAFC",
        ink: "#14233F",
        mute: "#566580",
        rule: "#CAD4DF",
        quantum: "#5A47D1",
        accept: "#0E7A55",
        reject: "#C23A2F",
        caution: "#9A6200",
        s1: "#2a78d6", // OPERATOR frames
        s2: "#eb6834", // PASS_OPEN frames
        s3: "#1baf7a", // ADMIN frames
      },
      fontFamily: {
        sans: ["Barlow", "system-ui", "sans-serif"],
        cond: ["'Barlow Condensed'", "Barlow", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
