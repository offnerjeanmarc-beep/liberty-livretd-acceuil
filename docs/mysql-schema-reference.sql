-- Référence MySQL production Conciergerie Liberty.
-- SQLite est réservé au développement local.
CREATE TABLE properties (
  id INT AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(120) NOT NULL UNIQUE,
  name VARCHAR(180) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'active',
  city VARCHAR(120) NOT NULL DEFAULT '',
  cover_image VARCHAR(255) NOT NULL DEFAULT '/assets/liberty-hero.png',
  traveler_password_hash VARCHAR(255) NOT NULL,
  openai_api_key TEXT NOT NULL,
  openai_model VARCHAR(80) NOT NULL DEFAULT 'gpt-5.5',
  ai_instructions TEXT NOT NULL,
  welcome TEXT NOT NULL,
  address TEXT NOT NULL,
  gps VARCHAR(120) NOT NULL,
  wifi_ssid VARCHAR(180) NOT NULL DEFAULT '',
  wifi_password VARCHAR(180) NOT NULL DEFAULT '',
  ai_daily_limit INT NOT NULL DEFAULT 80,
  ai_session_limit INT NOT NULL DEFAULT 20,
  ai_max_input_chars INT NOT NULL DEFAULT 700,
  public_description TEXT NOT NULL,
  direct_booking_json LONGTEXT NOT NULL,
  data_json LONGTEXT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE TABLE service_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  property_id INT NOT NULL,
  type VARCHAR(120) NOT NULL,
  guest_name VARCHAR(180) NOT NULL DEFAULT '',
  message TEXT NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'new',
  created_at VARCHAR(40) NOT NULL,
  INDEX(property_id),
  FOREIGN KEY(property_id) REFERENCES properties(id)
);

CREATE TABLE chat_messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  property_id INT NOT NULL,
  role VARCHAR(40) NOT NULL,
  content TEXT NOT NULL,
  session_id VARCHAR(80) NOT NULL DEFAULT '',
  created_at VARCHAR(40) NOT NULL,
  INDEX(property_id),
  FOREIGN KEY(property_id) REFERENCES properties(id)
);

CREATE TABLE crm_leads (
  id INT AUTO_INCREMENT PRIMARY KEY,
  property_id INT NOT NULL,
  first_name VARCHAR(120) NOT NULL DEFAULT '',
  email VARCHAR(180) NOT NULL DEFAULT '',
  phone VARCHAR(80) NOT NULL DEFAULT '',
  stay_dates VARCHAR(160) NOT NULL DEFAULT '',
  marketing_consent TINYINT(1) NOT NULL DEFAULT 0,
  created_at VARCHAR(40) NOT NULL,
  INDEX(property_id),
  FOREIGN KEY(property_id) REFERENCES properties(id)
);

CREATE TABLE analytics_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  property_id INT NULL,
  event_name VARCHAR(120) NOT NULL,
  event_value VARCHAR(255) NOT NULL DEFAULT '',
  session_id VARCHAR(80) NOT NULL DEFAULT '',
  created_at VARCHAR(40) NOT NULL,
  INDEX(property_id),
  INDEX(event_name),
  FOREIGN KEY(property_id) REFERENCES properties(id)
);

CREATE TABLE city_pois (
  id INT AUTO_INCREMENT PRIMARY KEY,
  city VARCHAR(120) NOT NULL,
  type VARCHAR(80) NOT NULL,
  title VARCHAR(180) NOT NULL,
  description TEXT NOT NULL,
  distance VARCHAR(80) NOT NULL DEFAULT '',
  address VARCHAR(255) NOT NULL DEFAULT '',
  maps_url VARCHAR(500) NOT NULL DEFAULT '',
  external_url VARCHAR(500) NOT NULL DEFAULT '',
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  INDEX(city),
  INDEX(type)
);

CREATE TABLE property_pois (
  property_id INT NOT NULL,
  poi_id INT NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  PRIMARY KEY(property_id, poi_id),
  FOREIGN KEY(property_id) REFERENCES properties(id),
  FOREIGN KEY(poi_id) REFERENCES city_pois(id)
);

CREATE TABLE admin_settings (
  `key` VARCHAR(120) PRIMARY KEY,
  value TEXT NOT NULL
);

