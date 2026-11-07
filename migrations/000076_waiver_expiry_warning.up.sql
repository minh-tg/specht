-- When the server told people that an approved waiver is about to end, so it tells
-- them once. A waiver that lapses unannounced turns a green pipeline red.
ALTER TABLE waivers ADD COLUMN expiry_warned_at TIMESTAMPTZ;
