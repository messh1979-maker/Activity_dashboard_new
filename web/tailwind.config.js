/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Vazirmatn', 'IRANSans', 'system-ui', 'Tahoma', 'sans-serif'],
      },
      colors: {
        brand: {
          50: '#eef4ff',
          100: '#dbe6fe',
          200: '#bfd3fe',
          300: '#93b4fd',
          400: '#608dfa',
          500: '#3b66f6',
          600: '#2549eb',
          700: '#1d37d8',
          800: '#1e30af',
          900: '#1e2f8a',
        },
      },
      boxShadow: {
        card: '0 1px 3px rgb(16 24 40 / 0.08), 0 4px 16px -4px rgb(16 24 40 / 0.12)',
        pop: '0 8px 32px -8px rgb(16 24 40 / 0.25)',
      },
      borderRadius: {
        xl2: '1.25rem',
      },
    },
  },
  plugins: [],
}
