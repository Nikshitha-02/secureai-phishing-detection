/**
 * evaluation/splitDataset.ts
 * ──────────────────────────
 * Deterministic, reproducible train/test split.
 *
 * SPLIT STRATEGY
 * ──────────────
 * We use a fixed seed-based selection (every 5th entry → held-out test set)
 * rather than random shuffling, so:
 *   - Results are bit-for-bit identical across runs
 *   - No external RNG library is needed
 *   - The split is defined by index arithmetic, not randomness
 *
 * This means given the same DATASET array the split is always the same.
 *
 * RATIO: 80% development / 20% held-out test
 *
 * STRATIFICATION
 * ──────────────
 * We stratify by ground-truth label so each category maintains the same
 * approximate proportion in both sets. Without stratification, a 20% sample
 * of 80 entries could randomly land all SAFE or all PHISHING.
 *
 * Every 5th entry (index 0,4,9,...) within each label group goes to held-out.
 * The rest go to development.
 */

import type { DatasetEntry, GroundTruth } from './dataset';

export interface DatasetSplit {
  development: DatasetEntry[];
  heldOut:     DatasetEntry[];
}

/**
 * Splits the dataset deterministically into development and held-out sets.
 * Every 5th entry (0-indexed) within each label group is held out.
 *
 * @param entries  The full labeled dataset
 * @returns        { development, heldOut }
 */
export function splitDataset(entries: DatasetEntry[]): DatasetSplit {
  const development: DatasetEntry[] = [];
  const heldOut:     DatasetEntry[] = [];

  // Group by ground truth
  const labels: GroundTruth[] = ['SAFE', 'SUSPICIOUS', 'PHISHING'];

  for (const label of labels) {
    const group = entries.filter((e) => e.groundTruth === label);

    group.forEach((entry, i) => {
      // Every 5th element (i % 5 === 4) goes to held-out (20%)
      if (i % 5 === 4) {
        heldOut.push(entry);
      } else {
        development.push(entry);
      }
    });
  }

  return { development, heldOut };
}
