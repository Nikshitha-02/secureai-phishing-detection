import { Navbar } from '@/components/Navbar';
import { Hero } from '@/components/Hero';
import { FeatureCards } from '@/components/FeatureCards';
import { Statistics } from '@/components/Statistics';
import { Footer } from '@/components/Footer';

/**
 * LandingPage
 *
 * Composes the full public-facing landing page in section order:
 * Navbar → Hero → Features → Statistics → Footer
 *
 * All child components are self-contained with their own animations
 * and accessibility attributes. This page component only handles layout.
 */
export function LandingPage() {
  return (
    <div className="min-h-screen bg-gray-950 text-white antialiased">
      <Navbar />

      <main id="main-content">
        <Hero />
        <FeatureCards />
        <Statistics />
      </main>

      <Footer />
    </div>
  );
}
