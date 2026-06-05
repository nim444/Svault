import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// shadcn's class combiner: merge conditional classes and de-dupe Tailwind utils.
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
