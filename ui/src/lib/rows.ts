import type { Bytes } from "./api";

/** One ranked line in a breakdown column. */
export interface Row<T> {
  key: string;
  label: string;
  title?: string;
  bytes: Bytes;
  item: T;
}
