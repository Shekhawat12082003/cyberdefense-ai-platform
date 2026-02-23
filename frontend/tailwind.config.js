/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        'neon-red':   '#ff003c',
        'neon-blue':  '#00d4ff',
        'neon-green': '#00ff88',
      }
    },
  },
  plugins: [],
}