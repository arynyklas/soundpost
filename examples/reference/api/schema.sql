-- Copyright 2026 Aryn Yklas
-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE IF NOT EXISTS catalog (
  item text PRIMARY KEY,
  price_cents int NOT NULL
);
INSERT INTO catalog(item, price_cents) VALUES ('sku-100', 1250), ('sku-200', 4999)
  ON CONFLICT (item) DO NOTHING;
CREATE TABLE IF NOT EXISTS orders (
  id bigserial PRIMARY KEY,
  item text,
  quantity int,
  note text,
  channel text,
  status text
);
CREATE TABLE IF NOT EXISTS catalog_refresh (
  run_id text,
  attempt int,
  completion text
);
