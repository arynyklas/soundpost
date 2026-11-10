// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Receipt rendering for the order page. Only item, quantity, status and price are rendered; never the note or the summary.

/** The order object the API answers with (a subset; unknown fields are ignored). */
export interface Order {
  readonly order_id: number;
  readonly item: string;
  readonly quantity: number;
  readonly total_cents: number | null;
  readonly status: string;
}

/** An order the catalog could not price cannot be rendered as a receipt. */
export class UnpricedOrderError extends Error {
  constructor() {
    super("order_unpriced");
    this.name = "UnpricedOrderError";
  }
}

export function formatReceipt(order: Order): string {
  if (order.total_cents === null) {
    throw new UnpricedOrderError();
  }
  return `Order #${order.order_id}: ${order.quantity} x ${order.item} = $${(order.total_cents / 100).toFixed(2)} (${order.status})`;
}
