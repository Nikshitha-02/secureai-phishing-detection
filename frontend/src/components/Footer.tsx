import { Shield, Code2, MessageSquare, Globe } from 'lucide-react';

const footerLinks = {
  Product: [
    { label: 'URL Scanner', href: '#' },
    { label: 'Email Scanner', href: '#' },
    { label: 'AI Analysis', href: '#' },
    { label: 'Security Reports', href: '#' },
  ],
  Company: [
    { label: 'About', href: '#' },
    { label: 'Blog', href: '#' },
    { label: 'Careers', href: '#' },
    { label: 'Contact', href: '#' },
  ],
  Legal: [
    { label: 'Privacy Policy', href: '#' },
    { label: 'Terms of Service', href: '#' },
    { label: 'Cookie Policy', href: '#' },
  ],
};

const socials = [
  { icon: Code2, label: 'GitHub', href: '#' },
  { icon: MessageSquare, label: 'Twitter / X', href: '#' },
  { icon: Globe, label: 'LinkedIn', href: '#' },
];

export function Footer() {
  return (
    <footer
      className="border-t border-white/5 bg-gray-950 px-4 pt-16 pb-8 sm:px-6 lg:px-8"
      aria-label="Site footer"
    >
      <div className="mx-auto max-w-7xl">
        {/* Top row — brand + links */}
        <div className="grid gap-12 sm:grid-cols-2 lg:grid-cols-5 mb-12">
          {/* Brand */}
          <div className="lg:col-span-2">
            <a
              href="#"
              className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded-md w-fit"
              aria-label="SecureAI – home"
            >
              <Shield className="h-6 w-6 text-cyan-400" aria-hidden="true" />
              <span className="text-lg font-bold text-white">
                Secure<span className="text-cyan-400">AI</span>
              </span>
            </a>
            <p className="mt-4 max-w-xs text-sm leading-relaxed text-gray-500">
              AI-powered phishing detection that explains every threat in plain
              language. Stay secure without needing a security degree.
            </p>

            {/* Social icons */}
            <div className="mt-6 flex gap-4" aria-label="Social media links">
              {socials.map((s) => (
                <a
                  key={s.label}
                  href={s.href}
                  aria-label={s.label}
                  className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 text-gray-400
                    hover:border-cyan-500/40 hover:text-cyan-400 transition-colors
                    focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
                >
                  <s.icon className="h-4 w-4" aria-hidden="true" />
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          {Object.entries(footerLinks).map(([group, links]) => (
            <div key={group}>
              <h3 className="text-xs font-semibold uppercase tracking-widest text-gray-300 mb-4">
                {group}
              </h3>
              <ul className="space-y-3" role="list">
                {links.map((link) => (
                  <li key={link.label}>
                    <a
                      href={link.href}
                      className="text-sm text-gray-500 hover:text-gray-200 transition-colors
                        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded"
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom row — copyright */}
        <div className="flex flex-col items-center gap-2 border-t border-white/5 pt-8 text-center sm:flex-row sm:justify-between">
          <p className="text-xs text-gray-600">
            &copy; {new Date().getFullYear()} SecureAI. All rights reserved.
          </p>
          <p className="text-xs text-gray-700">
            Built with React · TypeScript · Tailwind CSS · Google Gemini
          </p>
        </div>
      </div>
    </footer>
  );
}
